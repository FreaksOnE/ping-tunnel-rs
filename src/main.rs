use std::io;

use anyhow::Result;
use clap::Parser;
use human_panic::setup_panic;
use tracing_appender::rolling;
use tracing_appender::rolling::RollingFileAppender;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;

use ping_tunnel_rs::cli::Arguments;

#[tokio::main]
async fn main() -> Result<()> {
    setup_panic!();

    let arguments = Arguments::parse();

    let file_writer = match log_file_writer() {
        Ok(writer) => writer,
        Err(e) => {
            eprintln!("warning: file logging disabled: {e}");
            BoxMakeWriter::new(io::sink)
        }
    };

    let subscriber = tracing_subscriber::registry()
        .with(
            EnvFilter::from_default_env()
                .add_directive(arguments.log_level.into())
                .add_directive("reqwest=off".parse().map_err(|e| {
                    anyhow::anyhow!("invalid reqwest tracing directive: {e}")
                })?)
                .add_directive("hyper=off".parse().map_err(|e| {
                    anyhow::anyhow!("invalid hyper tracing directive: {e}")
                })?),
        )
        .with(
            fmt::Layer::new()
                .with_writer(io::stdout)
                .with_timer(tracing_subscriber::fmt::time::time())
                .with_target(false)
                .with_level(true)
                .with_ansi(false),
        )
        .with(
            fmt::Layer::new()
                .with_writer(file_writer)
                .with_timer(tracing_subscriber::fmt::time::time())
                .with_target(false)
                .with_level(true)
                .with_ansi(false),
        );

    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        anyhow::anyhow!("failed to install tracing subscriber: {e}")
    })?;

    ping_tunnel_rs::run(arguments).await
}

fn log_file_writer() -> Result<BoxMakeWriter> {
    let debug_file = RollingFileAppender::builder()
        .rotation(rolling::Rotation::HOURLY)
        .filename_prefix("debug")
        .build("./logs")
        .map_err(|e| {
            anyhow::anyhow!("cannot write log files in ./logs: {e:?}")
        })?;
    let warn_file = RollingFileAppender::builder()
        .rotation(rolling::Rotation::DAILY)
        .filename_prefix("warnings")
        .build("./logs")
        .map_err(|e| {
            anyhow::anyhow!("cannot write log files in ./logs: {e:?}")
        })?
        .with_max_level(tracing::Level::WARN);
    Ok(BoxMakeWriter::new(debug_file.and(warn_file)))
}
