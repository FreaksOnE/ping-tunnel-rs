use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use tracing::Level;
use uuid::Uuid;
use uuid::Version;

use crate::ClientId;
use crate::constants::SESSION_TIMEOUT;
use crate::crypto;

#[derive(Parser, Debug)]
pub struct Arguments {
    #[clap(subcommand)]
    pub command: Commands,

    #[arg(long, default_value_t = Level::WARN)]
    pub log_level: Level,

    #[arg(long, default_value = "tun0")]
    pub tun_name: String,

    /// 16-bit tunnel discriminator placed in the ICMP identifier field.
    /// All peers must use the same value. Must be non-zero.
    #[arg(long, default_value_t = 1)]
    pub icmp_identifier: u16,

    /// mtu of the network gateway
    #[arg(long, default_value_t = 1500)]
    pub outer_mtu: u16,

    /// Skip replacing the default route with the tunnel: without this flag the
    /// client points the default route into the TUN device (pinning the
    /// server's outer IP outside the tunnel so the ICMP transport keeps
    /// flowing) and restores the original routes on exit
    #[clap(short = 'r', long)]
    pub skip_route: bool,

    /// ip to listen for icmp packets, defaults to "0.0.0.0"
    #[arg(long, default_value_t = Ipv4Addr::new(0, 0, 0, 0))]
    pub listen_ip: Ipv4Addr,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Client {
        /// Client ID that is registered on the server. Must be a uuid v7.
        #[arg(long, value_parser = parse_client_id)]
        client_id: Uuid,

        /// Client password (required)
        #[arg(long, value_parser = parse_password)]
        password: String,

        /// Real (outer) IP address of the server
        #[arg(long)]
        server_ip: Ipv4Addr,
    },
    Server {
        /// uuid:password pairs, comma-separated
        #[arg(long, required = true)]
        clients: Vec<ClientEntries>,

        /// Drop a client session after this many seconds without a packet from
        /// that client; the client is told to re-authenticate
        #[arg(
            long,
            default_value_t = SESSION_TIMEOUT.as_secs(),
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        session_timeout: u64,

        /// Network interface client traffic is forwarded out of: the WAN side
        /// the masquerade rule binds to
        #[arg(long, default_value = "eth0")]
        out_interface: String,

        /// Skip the automatic NAT setup (net.ipv4.ip_forward and the iptables
        /// masquerade/forward rules)
        #[clap(long)]
        skip_nat: bool,
    },
}

/// Parses a client id: a uuid v7 (version 7, sorted random).
fn parse_client_id(s: &str) -> Result<Uuid, String> {
    let uuid = Uuid::parse_str(s).map_err(|e| {
        format!("invalid client id {s:?}: must be a uuid v7 (version 7, sorted random): {e}")
    })?;
    match uuid.get_version() {
        Some(Version::SortRand) => Ok(uuid),
        version => Err(format!(
            "invalid client id {s:?}: must be a uuid v7 (version 7, sorted random); got {version:?}"
        )),
    }
}

fn parse_password(s: &str) -> Result<String, String> {
    if s.is_empty() {
        return Err("password must not be empty".to_owned());
    }
    Ok(s.to_owned())
}

#[derive(Debug, Clone, Default)]
pub struct ClientEntries(BTreeMap<ClientId, [u8; 32]>);

impl FromStr for ClientEntries {
    type Err = String;

    /// Empty pieces (trailing commas) are skipped. Duplicate client ids keep the
    /// last password.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut entries = BTreeMap::new();
        for pair in value.split(',').filter(|piece| !piece.is_empty()) {
            let (client_id, key) = parse_client_entry(pair)?;
            insert_entry(&mut entries, client_id, key);
        }
        Ok(Self(entries))
    }
}

/// Merges the `--clients` values into the server allowlist.
///
/// Values are merged in command-line order, so for duplicate client ids the last
/// password wins.
pub fn into_allowlist(
    values: Vec<ClientEntries>,
) -> BTreeMap<ClientId, [u8; 32]> {
    let mut allowlist = BTreeMap::new();
    for (client_id, key) in values.into_iter().flat_map(|entries| entries.0) {
        insert_entry(&mut allowlist, client_id, key);
    }
    allowlist
}

/// Records one allowlist entry, warning when it replaces an earlier password.
fn insert_entry(
    allowlist: &mut BTreeMap<ClientId, [u8; 32]>,
    client_id: ClientId,
    key: [u8; 32],
) {
    if allowlist.insert(client_id.clone(), key).is_some() {
        tracing::warn!(client_id = ?client_id, "duplicate client entry: last password wins");
    }
}

/// Parses one `uuid:password` pair into its client id and derived session key.
///
/// The pair is split on its first `:`, so passwords may contain `:`.
fn parse_client_entry(pair: &str) -> Result<(ClientId, [u8; 32]), String> {
    let Some((id, password)) = pair.split_once(':') else {
        return Err(format!(
            "invalid client entry {pair:?}: missing `:` separator (expected uuid:password)"
        ));
    };
    if password.is_empty() {
        return Err(format!("invalid client entry {pair:?}: missing password"));
    }
    let uuid = Uuid::parse_str(id).map_err(|e| {
        format!("invalid client entry {pair:?}: invalid client id uuid: {e}")
    })?;
    let client_id = ClientId(uuid);
    let key = crypto::derive_key(password, client_id.0.as_bytes());
    Ok((client_id, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses one `--clients` value the way clap does.
    fn entries(value: &str) -> ClientEntries {
        value.parse().expect("valid --clients value")
    }

    /// Parses a full `server` command line the way clap does.
    fn parse_server(extra: &[&str]) -> Result<Arguments, clap::Error> {
        let mut argv = vec![
            "ping-tunnel-rs".to_owned(),
            "server".to_owned(),
            "--clients".to_owned(),
            format!("{}:pw", Uuid::nil()),
        ];
        argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
        Arguments::try_parse_from(argv)
    }

    /// Extracts the server subcommand's arguments.
    fn server_args(extra: &[&str]) -> (Vec<ClientEntries>, u64, String, bool) {
        match parse_server(extra).expect("valid server command line").command {
            Commands::Server {
                clients,
                session_timeout,
                out_interface,
                skip_nat,
            } => (clients, session_timeout, out_interface, skip_nat),
            other => panic!("expected the server subcommand, got {other:?}"),
        }
    }

    /// Parses a full `client` command line the way clap does.
    ///
    /// `top_level` holds global flags, which clap accepts only before the
    /// subcommand (like `--tun-name`).
    fn parse_client(top_level: &[&str]) -> Result<Arguments, clap::Error> {
        let mut argv = vec!["ping-tunnel-rs".to_owned()];
        argv.extend(top_level.iter().map(|arg| (*arg).to_owned()));
        argv.extend([
            "client".to_owned(),
            "--client-id".to_owned(),
            // A uuid v7, as the parser requires (the README example id).
            "01a13418-d2e5-702f-ac29-926d88dc625f".to_owned(),
            "--password".to_owned(),
            "pw".to_owned(),
            "--server-ip".to_owned(),
            "1.2.3.4".to_owned(),
        ]);
        Arguments::try_parse_from(argv)
    }

    #[test]
    fn test_log_level_flag() {
        // Default: WARN, so routine info/debug output stays quiet...
        let arguments = parse_client(&[]).expect("valid client command line");
        assert_eq!(arguments.log_level, Level::WARN);

        // ...and `--log-level` raises it, by name.
        for (value, expected) in
            [("debug", Level::DEBUG), ("INFO", Level::INFO)]
        {
            let arguments = parse_client(&["--log-level", value])
                .expect("valid --log-level value");
            assert_eq!(arguments.log_level, expected, "--log-level {value}");
        }

        // Unknown names are rejected by clap.
        assert!(parse_client(&["--log-level", "verbose"]).is_err());
    }

    #[test]
    fn test_skip_route_flag() {
        // By default the client replaces the default route with the tunnel...
        assert!(
            !parse_client(&[]).expect("valid client command line").skip_route
        );

        // ...and `--skip-route` (`-r`) opts out of route management.
        for flag in ["--skip-route", "-r"] {
            assert!(
                parse_client(&[flag])
                    .expect("valid client command line")
                    .skip_route,
                "{flag} must enable skip_route"
            );
        }
    }

    #[test]
    fn test_session_timeout_flag() {
        // Default: the session timeout constant, in seconds.
        let (_, default_timeout, _, _) = server_args(&[]);
        assert_eq!(default_timeout, SESSION_TIMEOUT.as_secs());

        // An operator can shorten or lengthen it...
        let (_, timeout, _, _) = server_args(&["--session-timeout", "5"]);
        assert_eq!(timeout, 5);

        // ...but zero would drop every session the moment it is created.
        assert!(parse_server(&["--session-timeout", "0"]).is_err());
    }

    #[test]
    fn test_out_interface_and_skip_nat_flags() {
        // Default: masquerade out of eth0, with the NAT setup enabled...
        let (out_interface, skip_nat) = {
            let (_, _, out_interface, skip_nat) = server_args(&[]);
            (out_interface, skip_nat)
        };
        assert_eq!(out_interface, "eth0");
        assert!(!skip_nat);

        // ...and both are overridable: the WAN interface by name, the NAT
        // setup by flag (for operators who manage the firewall by hand).
        let (out_interface, skip_nat) = {
            let (_, _, out_interface, skip_nat) =
                server_args(&["--out-interface", "ens5", "--skip-nat"]);
            (out_interface, skip_nat)
        };
        assert_eq!(out_interface, "ens5");
        assert!(skip_nat);
    }

    #[test]
    fn test_parse_allowlist_valid() {
        let values = vec![entries(&format!("{}:pw", Uuid::nil()))];
        let allowlist = into_allowlist(values);

        let expected_key = crypto::derive_key("pw", Uuid::nil().as_bytes());
        assert_eq!(allowlist.len(), 1);
        assert_eq!(allowlist.get(&ClientId(Uuid::nil())), Some(&expected_key));
    }

    #[test]
    fn test_parse_allowlist_multiple() {
        // Both shapes work: several pairs in one comma-separated value, and one
        // pair per value.
        let values = vec![
            entries(&format!(
                "{}:pw-one,{}:pw-two",
                Uuid::from_u128(1),
                Uuid::from_u128(2)
            )),
            entries(&format!("{}:pw-three", Uuid::from_u128(3))),
        ];
        let allowlist = into_allowlist(values);
        assert_eq!(allowlist.len(), 3);
    }

    #[test]
    fn test_parse_allowlist_skips_empty_pieces() {
        // Trailing commas are tolerated.
        let allowlist = into_allowlist(vec![entries(&format!(
            "{}:pw,",
            Uuid::from_u128(1)
        ))]);
        assert_eq!(allowlist.len(), 1);
    }

    #[test]
    fn test_parse_allowlist_duplicate_keeps_last() {
        let client_id = Uuid::from_u128(1);
        let values = vec![
            entries(&format!("{client_id}:first,{client_id}:second")),
            entries(&format!("{client_id}:third")),
        ];
        let allowlist = into_allowlist(values);
        assert_eq!(allowlist.len(), 1);
        assert_eq!(
            allowlist.get(&ClientId(client_id)),
            Some(&crypto::derive_key("third", client_id.as_bytes()))
        );
    }

    #[test]
    fn test_parse_allowlist_password_may_contain_colon() {
        let client_id = Uuid::from_u128(1);
        let allowlist =
            into_allowlist(vec![entries(&format!("{client_id}:a:b"))]);
        assert_eq!(
            allowlist.get(&ClientId(client_id)),
            Some(&crypto::derive_key("a:b", client_id.as_bytes()))
        );
    }

    #[test]
    fn test_parse_allowlist_invalid_uuid() {
        let err = "not-a-uuid:pw"
            .parse::<ClientEntries>()
            .expect_err("invalid uuid must fail");
        assert!(err.contains("invalid client entry"));
    }

    #[test]
    fn test_parse_allowlist_missing_password() {
        // No separator at all.
        assert!(Uuid::nil().to_string().parse::<ClientEntries>().is_err());

        // Separator present but the password is empty.
        assert!(format!("{}:", Uuid::nil()).parse::<ClientEntries>().is_err());
    }
}
