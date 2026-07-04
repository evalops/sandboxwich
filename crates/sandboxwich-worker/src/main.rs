use clap::{Parser, Subcommand};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "sandboxwich-worker")]
#[command(about = "Host-side worker placeholder for sandbox orchestration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Capabilities,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Capabilities => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "worker": "sandboxwich-worker",
                    "capabilities": [
                        "lease_placeholder",
                        "vm_backend_pending",
                        "snapshot_backend_pending"
                    ]
                }))?
            );
        }
    }

    Ok(())
}
