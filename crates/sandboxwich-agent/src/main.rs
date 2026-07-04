use clap::{Parser, Subcommand};
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "sandboxwich-agent")]
#[command(about = "Guest-side agent placeholder for command and file operations")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Heartbeat,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Heartbeat => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "agent": "sandboxwich-agent",
                    "ready": true
                }))?
            );
        }
    }

    Ok(())
}
