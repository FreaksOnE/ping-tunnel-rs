pub mod auth;
pub mod cli;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod transport;

mod bootstrap;
mod client;
mod nat;
mod route;
mod server;
mod tun;

use std::time::Duration;

use anyhow::Result;
use uuid::Uuid;

use self::cli::Arguments;
use self::cli::Commands;
use self::cli::into_allowlist;
use self::client::Client;
use self::server::Server;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(pub Uuid);

pub async fn run(arguments: Arguments) -> Result<()> {
    match arguments.command {
        Commands::Server {
            clients,
            session_timeout,
            out_interface,
            skip_nat,
        } => {
            let server = Server {
                tun_name: arguments.tun_name,
                icmp_identifier: arguments.icmp_identifier,
                outer_mtu: arguments.outer_mtu,
                listen_ip: arguments.listen_ip,
                allowlist: into_allowlist(clients),
                session_timeout: Duration::from_secs(session_timeout),
                out_interface,
                skip_nat,
            };
            server.run().await?
        }
        Commands::Client { client_id, password, server_ip } => {
            let client = Client {
                client_id: ClientId(client_id),
                password,
                listen_ip: arguments.listen_ip,
                server_ip,
                tun_name: arguments.tun_name,
                icmp_identifier: arguments.icmp_identifier,
                outer_mtu: arguments.outer_mtu,
                skip_route: arguments.skip_route,
            };
            client.run().await?
        }
    }

    Ok(())
}
