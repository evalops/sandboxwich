use std::process::Command as ProcessCommand;

use anyhow::{Context, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use sandboxwich_core::{AgentCommandRequest, AgentCommandResult, AgentHealthResponse};

#[derive(Debug, Parser)]
#[command(name = "sandboxwich-agent")]
#[command(about = "Guest-side agent for command and file operations")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Heartbeat,
    Exec(ExecArgs),
}

#[derive(Debug, Args)]
struct ExecArgs {
    #[arg(long)]
    cwd: Option<String>,

    #[arg(long = "env", value_parser = parse_env)]
    env: Vec<(String, String)>,

    #[arg(trailing_var_arg = true, required = true)]
    argv: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Heartbeat => {
            println!(
                "{}",
                serde_json::to_string_pretty(&AgentHealthResponse {
                    ok: true,
                    agent: "sandboxwich-agent".to_string(),
                    ready: true,
                })?
            );
        }
        Command::Exec(args) => {
            let result = execute(AgentCommandRequest {
                argv: args.argv,
                cwd: args.cwd,
                env: args.env.into_iter().collect(),
            })?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if result.exit_code.unwrap_or(1) != 0 {
                std::process::exit(result.exit_code.unwrap_or(1));
            }
        }
    }

    Ok(())
}

fn execute(request: AgentCommandRequest) -> anyhow::Result<AgentCommandResult> {
    let Some((program, args)) = request.argv.split_first() else {
        bail!("argv must contain at least one item");
    };

    let started_at = Utc::now();
    let mut command = ProcessCommand::new(program);
    command.args(args);
    if let Some(cwd) = request.cwd {
        command.current_dir(cwd);
    }
    command.envs(request.env);

    let output = command.output().context("failed to execute command")?;
    let finished_at = Utc::now();

    Ok(AgentCommandResult {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        started_at,
        finished_at,
    })
}

fn parse_env(value: &str) -> Result<(String, String), String> {
    let Some((key, value)) = value.split_once('=') else {
        return Err("env vars must be formatted as key=value".to_string());
    };
    if key.trim().is_empty() {
        return Err("env var key cannot be empty".to_string());
    }
    Ok((key.to_string(), value.to_string()))
}
