//! Server-side NAT bootstrap: enables IPv4 forwarding and installs the
//! iptables rules that make the server a gateway for the tunnel subnet,
//! undoing both on exit.
//!
//! Three rules are needed (see [`rules`]): a POSTROUTING masquerade so replies
//! to forwarded client traffic can return, and two FORWARD accepts (tunnel ->
//! WAN, and WAN -> tunnel for established connections). The same tradeoff as
//! [`crate::route`] and [`crate::bootstrap`]: shell-outs through blocking
//! [`std::process`] calls — one batch at startup, one at shutdown, never on
//! the packet path. Automatic setup is Linux-only; elsewhere (or with
//! `--skip-nat`) the guard warns once and leaves forwarding and the firewall
//! to the operator.

use std::process::Command;

use anyhow::Context;
use anyhow::Result;

use crate::constants::SYSCTL_IP_FORWARD;
use crate::constants::TUN_SUBNET;

/// One iptables rule, without its verb: `table` selects the table (`None` =
/// the default `filter` table) and `args` is everything after the
/// `-A`/`-C`/`-D` verb, e.g. `["FORWARD", "-i", "tun0", ...]`.
type Rule = (Option<&'static str>, Vec<String>);

/// Builds one [`Rule`], owning its argument strings.
fn rule(table: Option<&'static str>, args: &[&str]) -> Rule {
    (table, args.iter().map(|s| (*s).to_owned()).collect())
}

/// The three rules that make the server a gateway for the tunnel subnet, in
/// install order.
///
/// The FORWARD rules reference the configured TUN device (not a hardcoded
/// `tun0`) and the WAN interface from `--out-interface`.
fn rules(tun_name: &str, out_interface: &str) -> Vec<Rule> {
    vec![
        // Masquerade the tunnel subnet out of the WAN interface so replies to
        // forwarded client traffic can find their way back.
        rule(
            Some("nat"),
            &[
                "POSTROUTING",
                "-s",
                TUN_SUBNET,
                "-o",
                out_interface,
                "-j",
                "MASQUERADE",
            ],
        ),
        rule(
            None,
            &["FORWARD", "-i", tun_name, "-o", out_interface, "-j", "ACCEPT"],
        ),
        rule(
            None,
            &[
                "FORWARD",
                "-i",
                out_interface,
                "-o",
                tun_name,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        ),
    ]
}

/// Renders one `iptables` invocation the way error messages quote it.
fn render(table: Option<&str>, verb: &str, args: &[String]) -> String {
    let mut parts = vec!["iptables".to_owned()];
    if let Some(table) = table {
        parts.push("-t".to_owned());
        parts.push(table.to_owned());
    }
    parts.push(verb.to_owned());
    parts.extend(args.iter().cloned());
    parts.join(" ")
}

/// Builds the `iptables` command for one invocation: `table` selects the
/// table (`None` = the default `filter` table), `verb` is `-A`/`-C`/`-D` and
/// `args` is the rest of the rule.
fn iptables_command(
    table: Option<&str>,
    verb: &str,
    args: &[String],
) -> Command {
    let mut command = Command::new("iptables");
    if let Some(table) = table {
        command.args(["-t", table]);
    }
    command.arg(verb).args(args);
    command
}

/// Runs one `iptables` invocation, failing on a nonzero exit.
fn execute(table: Option<&str>, verb: &str, args: &[String]) -> Result<()> {
    let rendered = render(table, verb, args);
    let output =
        iptables_command(table, verb, args).output().with_context(|| {
            format!(
                "failed to run `{rendered}` (is iptables installed? \
                 pass --skip-nat to manage forwarding and the firewall by hand)"
            )
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "`{rendered}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Whether `rule` is already in its table: `iptables -C` exits 0 when present
/// and 1 when absent; any other status is a real error.
///
/// The existence check makes installation idempotent: rules left behind by a
/// crashed run (a release build with `panic = "abort"` skips [`Drop`]) are
/// kept instead of duplicated.
fn rule_exists(table: Option<&str>, args: &[String]) -> Result<bool> {
    let rendered = render(table, "-C", args);
    let output = iptables_command(table, "-C", args)
        .output()
        .with_context(|| format!("failed to run `{rendered}`"))?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        code => anyhow::bail!(
            "`{rendered}` failed (exit {code:?}): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

/// Enables `net.ipv4.ip_forward`, returning the previous value for [`Drop`]
/// to restore (`None` when forwarding was already on).
fn enable_ip_forward() -> Result<Option<String>> {
    let original = std::fs::read_to_string(SYSCTL_IP_FORWARD)
        .map(|s| s.trim().to_owned())
        .with_context(|| format!("failed to read {SYSCTL_IP_FORWARD}"))?;
    if original == "1" {
        tracing::debug!("IPv4 forwarding already enabled");
        return Ok(None);
    }
    std::fs::write(SYSCTL_IP_FORWARD, "1").with_context(|| {
        format!("failed to enable IPv4 forwarding via {SYSCTL_IP_FORWARD}")
    })?;
    tracing::info!(previous = %original, "enabled IPv4 forwarding");
    Ok(Some(original))
}

/// RAII guard that turns the server into a gateway for the tunnel subnet and
/// undoes it on drop.
///
/// On drop only the rules this guard added are deleted and only the saved
/// `ip_forward` value is restored, so a rule that predates the tunnel (or a
/// forwarding setting the operator already had on) is left as it was.
pub struct NatGuard {
    tun_name: String,
    out_interface: String,
    /// The `ip_forward` value saved before it was set to `1`; `None` when
    /// forwarding was already on (or setup was skipped / unsupported).
    ip_forward_saved: Option<String>,
    /// The rules this guard added; only these are deleted on drop.
    rules_installed: Vec<Rule>,
}

impl NatGuard {
    /// Enables IPv4 forwarding and installs the tunnel's iptables rules.
    pub fn install(tun_name: &str, out_interface: &str) -> Result<Self> {
        let mut guard = Self {
            tun_name: tun_name.to_owned(),
            out_interface: out_interface.to_owned(),
            ip_forward_saved: None,
            rules_installed: Vec::new(),
        };

        if !cfg!(target_os = "linux") {
            tracing::warn!(
                tun_name,
                out_interface,
                "automatic NAT setup is only supported on Linux; enable IPv4 \
                 forwarding and add the iptables rules yourself (see README.md)"
            );
            return Ok(guard);
        }

        if let Err(e) = guard.install_linux() {
            guard.cleanup();
            return Err(e);
        }
        Ok(guard)
    }

    fn install_linux(&mut self) -> Result<()> {
        self.ip_forward_saved = enable_ip_forward()?;

        for (table, args) in rules(&self.tun_name, &self.out_interface) {
            if rule_exists(table, &args)? {
                tracing::debug!(
                    rule = %render(table, "-A", &args),
                    "iptables rule already present; not adding it"
                );
                continue;
            }
            execute(table, "-A", &args).with_context(|| {
                format!(
                    "failed to add iptables rule `{}`",
                    render(table, "-A", &args)
                )
            })?;
            self.rules_installed.push((table, args));
        }

        tracing::info!(
            tun_name = %self.tun_name,
            out_interface = %self.out_interface,
            "NAT rules installed; client traffic is forwarded out of the WAN interface"
        );
        Ok(())
    }

    fn cleanup(&mut self) {
        for (table, args) in &self.rules_installed {
            if let Err(e) = execute(*table, "-D", args) {
                tracing::warn!(error = %e, "failed to remove an iptables rule");
            }
        }
        if !self.rules_installed.is_empty() {
            tracing::info!("removed the NAT rules installed for the tunnel");
        }
        if let Some(original) = self.ip_forward_saved.take() {
            if let Err(e) = std::fs::write(SYSCTL_IP_FORWARD, &original) {
                tracing::error!(
                    path = SYSCTL_IP_FORWARD,
                    error = %e,
                    "failed to restore net.ipv4.ip_forward"
                );
            } else {
                tracing::info!(
                    path = SYSCTL_IP_FORWARD,
                    restored = %original,
                    "restored IPv4 forwarding setting"
                );
            }
        }
    }
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl std::fmt::Debug for NatGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatGuard")
            .field("tun_name", &self.tun_name)
            .field("out_interface", &self.out_interface)
            .field("ip_forward_saved", &self.ip_forward_saved)
            .field("rules_installed", &self.rules_installed.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_shape() {
        let rules = rules("tun0", "eth0");
        assert_eq!(rules.len(), 3);

        let (table, args) = &rules[0];
        assert_eq!(*table, Some("nat"));
        assert_eq!(
            args.join(" "),
            "POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE"
        );

        let (table, args) = &rules[1];
        assert_eq!(*table, None);
        assert_eq!(args.join(" "), "FORWARD -i tun0 -o eth0 -j ACCEPT");

        let (table, args) = &rules[2];
        assert_eq!(*table, None);
        assert_eq!(
            args.join(" "),
            "FORWARD -i eth0 -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        );
    }

    #[test]
    fn test_rules_use_the_configured_tun_name() {
        let rules = rules("tun-s", "ens5");
        assert_eq!(rules[1].1.join(" "), "FORWARD -i tun-s -o ens5 -j ACCEPT");
        assert_eq!(
            rules[2].1.join(" "),
            "FORWARD -i ens5 -o tun-s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        );
    }

    #[test]
    fn test_render() {
        assert_eq!(
            render(Some("nat"), "-A", &["POSTROUTING".to_owned()]),
            "iptables -t nat -A POSTROUTING"
        );
        assert_eq!(
            render(
                None,
                "-C",
                &["FORWARD".to_owned(), "-i".to_owned(), "tun0".to_owned()]
            ),
            "iptables -C FORWARD -i tun0"
        );
    }
}
