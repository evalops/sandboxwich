use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};

use anyhow::{Context, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, AgentFileReadResponse, AgentFileWriteRequest,
    AgentHealthResponse, AppendCommandOutputRequest, ClaimLeaseRequest, ClaimLeaseResponse,
    CommandOutputStream, CompleteLeaseRequest, FailLeaseRequest, GuestStatus, JobKind, LeaseId,
    LeaseResponse, SandboxId, UpdateGuestHealthRequest, WorkerJobResult, build_api_client,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command as ProcessCommand,
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "sandboxwich-agent")]
#[command(about = "Guest-side agent for command and file operations")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Heartbeat(HeartbeatArgs),
    Daemon(DaemonArgs),
    Exec(ExecArgs),
    WriteFile(FileWriteArgs),
    ReadFile(FileReadArgs),
}

#[derive(Debug, Args)]
struct HeartbeatArgs {
    #[arg(long, env = "SANDBOXWICH_API")]
    api: Option<String>,

    #[arg(long, env = "SANDBOXWICH_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long, env = "SANDBOXWICH_TENANT")]
    tenant: Option<String>,

    #[arg(long, env = "SANDBOXWICH_SANDBOX_ID")]
    sandbox_id: Option<Uuid>,
}

#[derive(Debug, Args)]
struct DaemonArgs {
    #[arg(long, env = "SANDBOXWICH_API", default_value = "http://127.0.0.1:3217")]
    api: String,

    #[arg(long, env = "SANDBOXWICH_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long, env = "SANDBOXWICH_TENANT")]
    tenant: Option<String>,

    #[arg(long, env = "SANDBOXWICH_SANDBOX_ID")]
    sandbox_id: Uuid,

    #[arg(long, env = "SANDBOXWICH_WORKER_ID")]
    worker_id: Option<Uuid>,

    #[arg(long)]
    lease_seconds: Option<u64>,

    #[arg(long, default_value_t = 5000)]
    heartbeat_interval_ms: u64,

    #[arg(long, default_value_t = 1000)]
    idle_sleep_ms: u64,

    #[arg(long)]
    max_iterations: Option<u64>,
}

#[derive(Debug, Args)]
struct ExecArgs {
    #[arg(long)]
    cwd: Option<String>,

    #[arg(long = "env", value_parser = parse_env)]
    env: Vec<(String, String)>,

    #[arg(long, env = "SANDBOXWICH_API")]
    api: Option<String>,

    #[arg(long, env = "SANDBOXWICH_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long, env = "SANDBOXWICH_TENANT")]
    tenant: Option<String>,

    #[arg(long)]
    lease_id: Option<Uuid>,

    #[arg(trailing_var_arg = true, required = true)]
    argv: Vec<String>,
}

#[derive(Debug, Args)]
struct FileWriteArgs {
    #[arg(long)]
    path: PathBuf,

    #[arg(long)]
    content: Option<String>,
}

#[derive(Debug, Args)]
struct FileReadArgs {
    #[arg(long)]
    path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Heartbeat(args) => heartbeat(args).await,
        Command::Daemon(args) => daemon(args).await,
        Command::Exec(args) => exec(args).await,
        Command::WriteFile(args) => write_file(args).await,
        Command::ReadFile(args) => read_file(args).await,
    }
}

async fn heartbeat(args: HeartbeatArgs) -> anyhow::Result<()> {
    let response = AgentHealthResponse {
        ok: true,
        agent: agent_version(),
        ready: true,
    };
    if let (Some(api), Some(sandbox_id)) = (args.api.as_deref(), args.sandbox_id) {
        let client = build_api_client(args.api_token.as_deref(), args.tenant.as_deref())?;
        post_guest_health(
            &client,
            api.trim_end_matches('/'),
            SandboxId(sandbox_id),
            GuestStatus::Ready,
            None,
        )
        .await?;
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn daemon(args: DaemonArgs) -> anyhow::Result<()> {
    let api = args.api.trim_end_matches('/').to_string();
    let client = build_api_client(args.api_token.as_deref(), args.tenant.as_deref())?;
    let sandbox_id = SandboxId(args.sandbox_id);
    let mut iterations = 0_u64;

    loop {
        if args
            .max_iterations
            .is_some_and(|max_iterations| iterations >= max_iterations)
        {
            break;
        }
        iterations += 1;
        post_guest_health(&client, &api, sandbox_id, GuestStatus::Ready, None).await?;

        if let Some(worker_id) = args.worker_id {
            if let Some(lease) = claim_lease(&client, &api, worker_id, args.lease_seconds)
                .await?
                .lease
            {
                if let Err(error) = handle_lease(&client, &api, lease).await {
                    post_guest_health(
                        &client,
                        &api,
                        sandbox_id,
                        GuestStatus::Unhealthy,
                        Some(error.to_string()),
                    )
                    .await?;
                }
            }
        }

        if args
            .max_iterations
            .is_some_and(|max_iterations| iterations >= max_iterations)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(args.idle_sleep_ms)).await;
    }

    Ok(())
}

async fn exec(args: ExecArgs) -> anyhow::Result<()> {
    let lease = args.lease_id.map(LeaseId);
    let client = if args.api.is_some() && lease.is_some() {
        Some(build_api_client(
            args.api_token.as_deref(),
            args.tenant.as_deref(),
        )?)
    } else {
        None
    };
    let api = args
        .api
        .as_deref()
        .map(str::trim)
        .map(|api| api.trim_end_matches('/'));
    let result = execute_streaming(
        AgentCommandRequest {
            argv: args.argv,
            cwd: args.cwd,
            env: args.env.into_iter().collect(),
        },
        client.as_ref(),
        api,
        lease,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    if result.exit_code.unwrap_or(1) != 0 {
        std::process::exit(result.exit_code.unwrap_or(1));
    }
    Ok(())
}

async fn write_file(args: FileWriteArgs) -> anyhow::Result<()> {
    let content = match args.content {
        Some(content) => content.into_bytes(),
        None => {
            let mut content = Vec::new();
            tokio::io::stdin().read_to_end(&mut content).await?;
            content
        }
    };
    if let Some(parent) = args.path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&args.path, &content).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&AgentFileWriteRequest {
            path: args.path.display().to_string(),
            content,
        })?
    );
    Ok(())
}

async fn read_file(args: FileReadArgs) -> anyhow::Result<()> {
    let content = tokio::fs::read(&args.path).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&AgentFileReadResponse {
            path: args.path.display().to_string(),
            content,
        })?
    );
    Ok(())
}

async fn claim_lease(
    client: &reqwest::Client,
    api: &str,
    worker_id: Uuid,
    lease_seconds: Option<u64>,
) -> anyhow::Result<ClaimLeaseResponse> {
    let response = client
        .post(format!("{api}/workers/{worker_id}/leases/claim"))
        .json(&ClaimLeaseRequest { lease_seconds })
        .send()
        .await?;
    decode_json(response).await
}

async fn handle_lease(
    client: &reqwest::Client,
    api: &str,
    lease: sandboxwich_core::JobLease,
) -> anyhow::Result<LeaseResponse> {
    if lease.job.kind != JobKind::RunCommand {
        let response = client
            .post(format!("{api}/leases/{}/fail", lease.id))
            .json(&FailLeaseRequest {
                error: "sandboxwich-agent daemon only handles run_command leases".to_string(),
                retry: false,
            })
            .send()
            .await?;
        return decode_json(response).await;
    }

    let request = agent_request_from_payload(&lease.job.payload)?;
    match execute_streaming(request, Some(client), Some(api), Some(lease.id)).await {
        Ok(result) if result.exit_code.unwrap_or(1) == 0 => {
            let response = client
                .post(format!("{api}/leases/{}/complete", lease.id))
                .json(&CompleteLeaseRequest {
                    result: Some(WorkerJobResult::RunCommand { result }),
                })
                .send()
                .await?;
            decode_json(response).await
        }
        Ok(result) => {
            let response = client
                .post(format!("{api}/leases/{}/fail", lease.id))
                .json(&FailLeaseRequest {
                    error: if result.stderr.is_empty() {
                        format!("command exited with {:?}", result.exit_code)
                    } else {
                        result.stderr
                    },
                    retry: false,
                })
                .send()
                .await?;
            decode_json(response).await
        }
        Err(error) => {
            let response = client
                .post(format!("{api}/leases/{}/fail", lease.id))
                .json(&FailLeaseRequest {
                    error: error.to_string(),
                    retry: false,
                })
                .send()
                .await?;
            decode_json(response).await
        }
    }
}

async fn execute_streaming(
    request: AgentCommandRequest,
    client: Option<&reqwest::Client>,
    api: Option<&str>,
    lease_id: Option<LeaseId>,
) -> anyhow::Result<AgentCommandResult> {
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
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn().context("failed to execute command")?;
    let stdout = child.stdout.take().context("failed to capture stdout")?;
    let stderr = child.stderr.take().context("failed to capture stderr")?;
    let stdout_task = tokio::spawn(stream_reader(
        stdout,
        CommandOutputStream::Stdout,
        client.cloned(),
        api.map(ToOwned::to_owned),
        lease_id,
    ));
    let stderr_task = tokio::spawn(stream_reader(
        stderr,
        CommandOutputStream::Stderr,
        client.cloned(),
        api.map(ToOwned::to_owned),
        lease_id,
    ));

    let status = child.wait().await.context("failed to wait for command")?;
    let stdout = stdout_task.await.context("stdout stream task failed")??;
    let stderr = stderr_task.await.context("stderr stream task failed")??;
    let finished_at = Utc::now();
    Ok(AgentCommandResult {
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        started_at,
        finished_at,
    })
}

async fn stream_reader<R>(
    mut reader: R,
    stream: CommandOutputStream,
    client: Option<reqwest::Client>,
    api: Option<String>,
    lease_id: Option<LeaseId>,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let chunk = &buffer[..count];
        captured.extend_from_slice(chunk);
        match stream {
            CommandOutputStream::Stdout => tokio::io::stdout().write_all(chunk).await?,
            CommandOutputStream::Stderr => tokio::io::stderr().write_all(chunk).await?,
        }
        if let (Some(client), Some(api), Some(lease_id)) = (&client, &api, lease_id) {
            append_output_chunk(
                client,
                api,
                lease_id,
                stream.clone(),
                String::from_utf8_lossy(chunk).into_owned(),
            )
            .await?;
        }
    }
    Ok(captured)
}

async fn append_output_chunk(
    client: &reqwest::Client,
    api: &str,
    lease_id: LeaseId,
    stream: CommandOutputStream,
    chunk: String,
) -> anyhow::Result<()> {
    if chunk.is_empty() {
        return Ok(());
    }
    let response = client
        .post(format!("{api}/leases/{lease_id}/output"))
        .json(&AppendCommandOutputRequest {
            stream,
            chunk,
            annotations: Vec::new(),
        })
        .send()
        .await?;
    let _: serde_json::Value = decode_json(response).await?;
    Ok(())
}

async fn post_guest_health(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    status: GuestStatus,
    message: Option<String>,
) -> anyhow::Result<()> {
    let response = client
        .post(format!("{api}/sandboxes/{sandbox_id}/guest-health"))
        .json(&UpdateGuestHealthRequest {
            status,
            agent_version: Some(agent_version()),
            checks: Some(serde_json::json!({
                "exec": {"status": "ok"},
                "files": {"status": "ok"}
            })),
            message,
        })
        .send()
        .await?;
    let _: serde_json::Value = decode_json(response).await?;
    Ok(())
}

fn agent_version() -> String {
    concat!("sandboxwich-agent/", env!("CARGO_PKG_VERSION")).to_string()
}

fn agent_request_from_payload(payload: &serde_json::Value) -> anyhow::Result<AgentCommandRequest> {
    let argv = payload
        .get("argv")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("job payload is missing argv"))?;
    let argv = serde_json::from_value(argv).context("job payload argv is invalid")?;
    let cwd = match payload.get("cwd") {
        Some(value) if !value.is_null() => {
            Some(serde_json::from_value(value.clone()).context("job payload cwd is invalid")?)
        }
        _ => None,
    };
    let env = payload
        .get("env")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("job payload env is invalid")?
        .unwrap_or_else(BTreeMap::new);
    Ok(AgentCommandRequest { argv, cwd, env })
}

async fn decode_json<T>(response: reqwest::Response) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("request failed with {status}: {body}");
    }
    serde_json::from_str(&body).context("failed to decode response body")
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
