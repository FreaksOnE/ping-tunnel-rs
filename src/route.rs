//! Client-side default-route management: while the tunnel runs, the IPv4
//! default route points into the TUN device; the host's original routes
//! come back when the client exits.
//!
//! Two details keep this from breaking the outer path:
//!
//! * Before the default route is replaced, the server's outer address is
//!   pinned outside the tunnel (a `/32` via the saved default route). Without
//!   that host route the outer ICMP packets to the server would match the
//!   tunnel default route and loop back into the tunnel itself.
//! * The saved default routes are re-installed by [`Drop`].
//!
//! Route changes shell out to `ip` (iproute2) through blocking [`std::process`]
//! calls.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::Context;
use anyhow::Result;

/// One saved IPv4 default route, reduced to the fields `ip route add` needs to
/// re-install it. The kernel's extra attributes (`proto`, `metric`, ...) are
/// neither restorable nor relevant to the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRoute {
    via: Option<Ipv4Addr>,
    dev: String,
}

impl DefaultRoute {
    /// The `ip` invocation that re-installs this saved default route.
    fn add_args(&self) -> Vec<String> {
        let mut args = vec![
            "-4".to_owned(),
            "route".to_owned(),
            "add".to_owned(),
            "default".to_owned(),
        ];
        if let Some(via) = self.via {
            args.push("via".to_owned());
            args.push(via.to_string());
        }
        args.push("dev".to_owned());
        args.push(self.dev.clone());
        args
    }
}

/// The `ip` invocation pinning `server_ip` outside the tunnel via the saved
/// default route.
fn pin_args(server_ip: Ipv4Addr, saved: &DefaultRoute) -> Vec<String> {
    let mut args = vec![
        "-4".to_owned(),
        "route".to_owned(),
        "add".to_owned(),
        format!("{server_ip}/32"),
    ];
    if let Some(via) = saved.via {
        args.push("via".to_owned());
        args.push(via.to_string());
    }
    args.push("dev".to_owned());
    args.push(saved.dev.clone());
    args
}

/// Parses `ip -4 route show default` output into restorable default routes.
fn parse_default_routes(output: &str) -> Vec<DefaultRoute> {
    let mut routes = Vec::new();
    for line in output.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match parse_default_route(line) {
            Some(route) => routes.push(route),
            None => tracing::warn!(
                line,
                "unparseable default route; it will not be restored"
            ),
        }
    }
    routes
}

/// Parses one `ip -4 route show default` line.
fn parse_default_route(line: &str) -> Option<DefaultRoute> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "default" {
        return None;
    }
    let mut via = None;
    let mut dev = None;
    while let Some(token) = tokens.next() {
        match token {
            "via" => via = Some(tokens.next()?.parse().ok()?),
            "dev" => dev = Some(tokens.next()?.to_owned()),
            _ => {}
        }
    }
    Some(DefaultRoute { via, dev: dev? })
}

/// Runs one `ip` (iproute2) invocation, returning its stdout.
fn ip<S: AsRef<str>>(args: &[S]) -> Result<String> {
    let rendered = args.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ");
    let output = Command::new("ip")
        .args(args.iter().map(AsRef::as_ref))
        .output()
        .with_context(|| {
            format!(
                "failed to run `ip {rendered}` (is iproute2 installed? \
                 pass --skip-route to manage routes by hand)"
            )
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "`ip {rendered}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Whether `ip` refused a `route add` because that route already exists.
fn is_route_exists(error: &anyhow::Error) -> bool {
    error.to_string().contains("File exists")
}

/// RAII guard that points the default route into the TUN device and restores
/// the host's routes on drop.
pub struct DefaultRouteGuard {
    tun_name: String,
    server_ip: Ipv4Addr,
    /// Default routes saved before the tunnel took over, re-installed on drop.
    saved: Vec<DefaultRoute>,
    /// Whether the server pin was added (and must be removed on drop).
    pin_installed: bool,
    /// Whether the tunnel default replaced the saved routes (and must be undone
    /// on drop).
    default_installed: bool,
}

impl DefaultRouteGuard {
    /// Points the IPv4 default route into `tun_name`.
    pub fn install(tun_name: &str, server_ip: Ipv4Addr) -> Result<Self> {
        let mut guard = Self {
            tun_name: tun_name.to_owned(),
            server_ip,
            saved: Vec::new(),
            pin_installed: false,
            default_installed: false,
        };

        if !cfg!(target_os = "linux") {
            tracing::warn!(
                tun_name,
                %server_ip,
                "automatic default-route setup is only supported on Linux; \
                 route the traffic you want tunneled into the TUN device yourself"
            );
            return Ok(guard);
        }

        guard.saved = parse_default_routes(
            &ip(&["-4", "route", "show", "default"])
                .context("failed to read the current default route")?,
        );

        match guard.saved.first() {
            Some(saved) => match ip(&pin_args(server_ip, saved)) {
                Ok(_) => guard.pin_installed = true,
                Err(e) if is_route_exists(&e) => {
                    tracing::debug!(
                        "a route to the server already exists; not pinning it"
                    );
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to pin the server's outer address outside the tunnel");
                }
            },
            None => tracing::warn!(
                %server_ip,
                "no default route to save; the server's outer address is not pinned — \
                 make sure it stays reachable outside the tunnel"
            ),
        }

        ip(&["-4", "route", "replace", "default", "dev", tun_name])
            .context("failed to point the default route into the tunnel")?;
        guard.default_installed = true;

        tracing::info!(
            tun_name,
            %server_ip,
            "default route now points into the tunnel"
        );
        Ok(guard)
    }

    pub fn reapply(&mut self) -> Result<()> {
        if !self.default_installed {
            return Ok(());
        }
        ip(&["-4", "route", "replace", "default", "dev", &self.tun_name])
            .context("failed to re-point the default route into the tunnel")?;
        tracing::debug!(
            tun_name = %self.tun_name,
            "re-pointed the default route into the tunnel"
        );
        Ok(())
    }
}

impl Drop for DefaultRouteGuard {
    fn drop(&mut self) {
        if self.default_installed {
            if let Err(e) =
                ip(&["-4", "route", "del", "default", "dev", &self.tun_name])
            {
                tracing::warn!(error = %e, "failed to remove the tunnel default route");
            }
            for saved in &self.saved {
                if let Err(e) = ip(&saved.add_args()) {
                    tracing::warn!(error = %e, "failed to restore a default route");
                }
            }
            tracing::info!(
                "removed the tunnel default route and restored the original ones"
            );
        }
        if self.pin_installed {
            let pin = format!("{}/32", self.server_ip);
            if let Err(e) = ip(&["-4", "route", "del", &pin]) {
                tracing::warn!(error = %e, "failed to remove the server pin route");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(via: Option<&str>, dev: &str) -> DefaultRoute {
        DefaultRoute {
            via: via.map(|v| v.parse().expect("valid gateway address")),
            dev: dev.to_owned(),
        }
    }

    #[test]
    fn test_parse_default_route_with_gateway() {
        let routes = parse_default_routes(
            "default via 192.168.88.1 dev br0 proto dhcp src 192.168.88.2 metric 100\n",
        );
        assert_eq!(routes, vec![route(Some("192.168.88.1"), "br0")]);
    }

    #[test]
    fn test_parse_default_route_without_gateway() {
        let routes = parse_default_routes("default dev ppp0 scope link\n");
        assert_eq!(routes, vec![route(None, "ppp0")]);
    }

    #[test]
    fn test_parse_default_routes_keeps_every_default() {
        let routes = parse_default_routes(
            "default via 192.0.2.1 dev eth0 metric 100\n\
             default via 198.51.100.1 dev eth1 metric 200\n",
        );
        assert_eq!(
            routes,
            vec![
                route(Some("192.0.2.1"), "eth0"),
                route(Some("198.51.100.1"), "eth1")
            ]
        );
    }

    #[test]
    fn test_parse_default_routes_skips_unrestorable_lines() {
        for output in [
            "default via 192.0.2.1\n",
            "default via oops dev eth0\n",
            "198.51.100.0/24 via 192.0.2.1 dev eth0\n",
            "\n",
        ] {
            assert!(
                parse_default_routes(output).is_empty(),
                "{output:?} must not be restorable"
            );
        }
    }

    #[test]
    fn test_restore_and_pin_args() {
        let with_gateway = route(Some("192.168.88.1"), "br0");
        assert_eq!(
            with_gateway.add_args().join(" "),
            "-4 route add default via 192.168.88.1 dev br0"
        );
        assert_eq!(
            pin_args("203.0.113.1".parse().unwrap(), &with_gateway).join(" "),
            "-4 route add 203.0.113.1/32 via 192.168.88.1 dev br0"
        );

        let without_gateway = route(None, "ppp0");
        assert_eq!(
            without_gateway.add_args().join(" "),
            "-4 route add default dev ppp0"
        );
        assert_eq!(
            pin_args("203.0.113.1".parse().unwrap(), &without_gateway)
                .join(" "),
            "-4 route add 203.0.113.1/32 dev ppp0"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_install_is_a_warned_noop_off_linux() {
        let guard =
            DefaultRouteGuard::install("tun0", "203.0.113.1".parse().unwrap())
                .expect("the unsupported-platform guard is a warned no-op");
        assert!(!guard.default_installed);
        assert!(!guard.pin_installed);
    }
}
