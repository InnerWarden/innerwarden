mod collectors;
mod config;
mod detectors;
mod sinks;

use anyhow::Result;
use clap::Parser;
use tracing::info;

#[derive(Parser)]
#[command(name = "innerwarden", version, about = "Lightweight host observability agent")]
struct Cli {
    /// Path to config file
    #[arg(long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)?;

    info!(
        host = %cfg.agent.host_id,
        data_dir = %cfg.output.data_dir,
        "innerwarden v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    info!("all systems nominal — no collectors active yet");

    Ok(())
}
