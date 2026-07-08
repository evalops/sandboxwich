use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

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

const DEFAULT_HEARTBEAT_FAILURE_THRESHOLD: u32 = 12;
/// Consecutive failures of the daemon's control-plane calls (lease claim, and the
/// guest-health report posted after a failed lease) before the daemon gives up and exits.
const DEFAULT_CLAIM_FAILURE_THRESHOLD: u32 = 12;
/// Ceiling for the exponential backoff applied between retried control-plane calls.
const MAX_CLAIM_BACKOFF: Duration = Duration::from_secs(30);
/// Default workspace root that agent file operations are confined to.
const DEFAULT_WORKSPACE_ROOT: &str = "/workspace";
/// Default cap on the size of a single file read or write.
const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Default cap on the in-memory stdout/stderr buffer captured per stream for a command's
/// final JSON result. Streaming chunks are forwarded to the API incrementally regardless of
/// this cap; this only bounds the local copy used to build the final result.
const DEFAULT_MAX_CAPTURED_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;

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

    #[arg(
        long,
        env = "SANDBOXWICH_HEARTBEAT_FAILURE_THRESHOLD",
        default_value_t = DEFAULT_HEARTBEAT_FAILURE_THRESHOLD
    )]
    heartbeat_failure_threshold: u32,

    /// Consecutive claim/health-report failures tolerated before the daemon exits.
    #[arg(
        long,
        env = "SANDBOXWICH_CLAIM_FAILURE_THRESHOLD",
        default_value_t = DEFAULT_CLAIM_FAILURE_THRESHOLD
    )]
    claim_failure_threshold: u32,

    #[arg(long, default_value_t = 1000)]
    idle_sleep_ms: u64,

    #[arg(long)]
    max_iterations: Option<u64>,

    /// Cap on the in-memory stdout/stderr buffer captured per stream for a command's result.
    #[arg(
        long,
        env = "SANDBOXWICH_MAX_CAPTURED_OUTPUT_BYTES",
        default_value_t = DEFAULT_MAX_CAPTURED_OUTPUT_BYTES
    )]
    max_captured_output_bytes: u64,
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

    /// Cap on the in-memory stdout/stderr buffer captured per stream for the result.
    #[arg(
        long,
        env = "SANDBOXWICH_MAX_CAPTURED_OUTPUT_BYTES",
        default_value_t = DEFAULT_MAX_CAPTURED_OUTPUT_BYTES
    )]
    max_captured_output_bytes: u64,

    #[arg(trailing_var_arg = true, required = true)]
    argv: Vec<String>,
}

#[derive(Debug, Args)]
struct FileWriteArgs {
    #[arg(long)]
    path: PathBuf,

    #[arg(long)]
    content: Option<String>,

    /// Root directory that file writes are confined to; paths escaping this root are rejected.
    #[arg(
        long,
        env = "SANDBOXWICH_WORKSPACE_ROOT",
        default_value = DEFAULT_WORKSPACE_ROOT
    )]
    workspace_root: PathBuf,

    /// Maximum number of bytes that may be written in a single call.
    #[arg(
        long,
        env = "SANDBOXWICH_MAX_FILE_BYTES",
        default_value_t = DEFAULT_MAX_FILE_BYTES
    )]
    max_bytes: u64,
}

#[derive(Debug, Args)]
struct FileReadArgs {
    #[arg(long)]
    path: PathBuf,

    /// Root directory that file reads are confined to; paths escaping this root are rejected.
    #[arg(
        long,
        env = "SANDBOXWICH_WORKSPACE_ROOT",
        default_value = DEFAULT_WORKSPACE_ROOT
    )]
    workspace_root: PathBuf,

    /// Maximum number of bytes that may be read in a single call.
    #[arg(
        long,
        env = "SANDBOXWICH_MAX_FILE_BYTES",
        default_value_t = DEFAULT_MAX_FILE_BYTES
    )]
    max_bytes: u64,
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
    let heartbeat_interval = Duration::from_millis(args.heartbeat_interval_ms.max(1));
    post_guest_health(&client, &api, sandbox_id, GuestStatus::Ready, None).await?;
    let heartbeat_task = tokio::spawn(heartbeat_loop(
        client.clone(),
        api.clone(),
        sandbox_id,
        heartbeat_interval,
        args.heartbeat_failure_threshold.max(1),
    ));

    // Tracks consecutive failures across both claim_lease and the guest-health report posted
    // after a failed lease: both represent reachability of the control plane, and a transient
    // blip in either should be retried with backoff rather than tearing down the daemon.
    let mut claim_budget = HeartbeatFailureBudget::new(args.claim_failure_threshold.max(1));
    let mut claim_backoff = Backoff::new(Duration::from_millis(args.idle_sleep_ms.max(1)));

    let daemon_result = async {
        loop {
            if heartbeat_task.is_finished() {
                bail!("heartbeat loop stopped");
            }
            if args
                .max_iterations
                .is_some_and(|max_iterations| iterations >= max_iterations)
            {
                break;
            }
            iterations += 1;

            if let Some(worker_id) = args.worker_id {
                let claim_response =
                    with_retry(&mut claim_budget, &mut claim_backoff, "claim_lease", || {
                        claim_lease(&client, &api, worker_id, args.lease_seconds)
                    })
                    .await?;

                if let Some(lease) = claim_response.lease {
                    if let Err(error) =
                        handle_lease(&client, &api, lease, args.max_captured_output_bytes).await
                    {
                        with_retry(
                            &mut claim_budget,
                            &mut claim_backoff,
                            "post_guest_health",
                            || {
                                post_guest_health(
                                    &client,
                                    &api,
                                    sandbox_id,
                                    GuestStatus::Unhealthy,
                                    Some(error.to_string()),
                                )
                            },
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
    .await;

    if heartbeat_task.is_finished() {
        heartbeat_task.await.context("heartbeat task failed")??;
    } else {
        heartbeat_task.abort();
        let _ = heartbeat_task.await;
    }

    daemon_result
}

async fn heartbeat_loop(
    client: reqwest::Client,
    api: String,
    sandbox_id: SandboxId,
    heartbeat_interval: Duration,
    heartbeat_failure_threshold: u32,
) -> anyhow::Result<()> {
    let mut failure_budget = HeartbeatFailureBudget::new(heartbeat_failure_threshold);
    loop {
        tokio::time::sleep(heartbeat_interval).await;
        match post_guest_health(&client, &api, sandbox_id, GuestStatus::Ready, None).await {
            Ok(()) => failure_budget.record_success(),
            Err(error) => {
                let warning = format!(
                    "sandboxwich-agent: heartbeat post failed ({}/{}): {error}\n",
                    failure_budget.consecutive_failures() + 1,
                    failure_budget.max_consecutive_failures(),
                );
                let _ = tokio::io::stderr().write_all(warning.as_bytes()).await;
                if failure_budget.record_failure() {
                    bail!(
                        "heartbeat failed {} consecutive times: {error}",
                        failure_budget.max_consecutive_failures()
                    );
                }
            }
        }
    }
}

struct HeartbeatFailureBudget {
    max_consecutive_failures: u32,
    consecutive_failures: u32,
}

impl HeartbeatFailureBudget {
    fn new(max_consecutive_failures: u32) -> Self {
        Self {
            max_consecutive_failures: max_consecutive_failures.max(1),
            consecutive_failures: 0,
        }
    }

    fn max_consecutive_failures(&self) -> u32 {
        self.max_consecutive_failures
    }

    fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    fn record_failure(&mut self) -> bool {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.consecutive_failures >= self.max_consecutive_failures
    }
}

/// Exponential backoff with a fixed ceiling, reset on success.
struct Backoff {
    base: Duration,
    max: Duration,
    current: Duration,
}

impl Backoff {
    fn new(base: Duration) -> Self {
        let base = base.max(Duration::from_millis(1));
        Self {
            base,
            max: MAX_CLAIM_BACKOFF.max(base),
            current: base,
        }
    }

    fn reset(&mut self) {
        self.current = self.base;
    }

    async fn wait(&mut self) {
        tokio::time::sleep(self.current).await;
        self.current = (self.current * 2).min(self.max);
    }
}

/// Error from a control-plane HTTP call, distinguishing transient/recoverable failures
/// (connection issues, timeouts, 5xx, 429) from failures that should not be retried.
#[derive(Debug)]
enum AgentRequestError {
    Transport(reqwest::Error),
    Status {
        status: reqwest::StatusCode,
        body: String,
    },
    Decode(serde_json::Error),
}

impl std::fmt::Display for AgentRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRequestError::Transport(error) => write!(f, "request failed: {error}"),
            AgentRequestError::Status { status, body } => {
                write!(f, "request failed with {status}: {body}")
            }
            AgentRequestError::Decode(error) => {
                write!(f, "failed to decode response body: {error}")
            }
        }
    }
}

impl std::error::Error for AgentRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AgentRequestError::Transport(error) => Some(error),
            AgentRequestError::Status { .. } => None,
            AgentRequestError::Decode(error) => Some(error),
        }
    }
}

impl From<reqwest::Error> for AgentRequestError {
    fn from(error: reqwest::Error) -> Self {
        AgentRequestError::Transport(error)
    }
}

impl AgentRequestError {
    /// Whether this failure looks transient (worth retrying) rather than a durable rejection.
    fn is_recoverable(&self) -> bool {
        match self {
            AgentRequestError::Transport(error) => {
                error.is_timeout() || error.is_connect() || error.is_request()
            }
            AgentRequestError::Status { status, .. } => {
                status.is_server_error()
                    || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || *status == reqwest::StatusCode::REQUEST_TIMEOUT
            }
            AgentRequestError::Decode(_) => false,
        }
    }
}

/// Runs `operation` in a loop, retrying with backoff while failures are recoverable, bailing
/// out of the surrounding daemon only once `budget` trips after sustained failure.
async fn with_retry<T, F, Fut>(
    budget: &mut HeartbeatFailureBudget,
    backoff: &mut Backoff,
    operation_name: &str,
    mut operation: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, AgentRequestError>>,
{
    loop {
        match operation().await {
            Ok(value) => {
                budget.record_success();
                backoff.reset();
                return Ok(value);
            }
            Err(error) if error.is_recoverable() => {
                let warning = format!(
                    "sandboxwich-agent: {operation_name} failed ({}/{}), retrying: {error}\n",
                    budget.consecutive_failures() + 1,
                    budget.max_consecutive_failures(),
                );
                let _ = tokio::io::stderr().write_all(warning.as_bytes()).await;
                if budget.record_failure() {
                    bail!(
                        "{operation_name} failed {} consecutive times: {error}",
                        budget.max_consecutive_failures()
                    );
                }
                backoff.wait().await;
            }
            Err(error) => {
                bail!("{operation_name} failed with a non-recoverable error: {error}");
            }
        }
    }
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
        args.max_captured_output_bytes,
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

    if content.len() as u64 > args.max_bytes {
        bail!(
            "refusing to write {} bytes: exceeds max-bytes limit of {}",
            content.len(),
            args.max_bytes
        );
    }

    let target = confine_to_workspace(&args.workspace_root, &args.path).await?;

    // Refuse to write through an existing non-regular file (directory, symlink, device, ...).
    if let Ok(metadata) = tokio::fs::symlink_metadata(&target).await {
        if !metadata.is_file() {
            bail!(
                "refusing to write to non-regular file at {}",
                target.display()
            );
        }
    }

    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&target, &content).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&AgentFileWriteRequest {
            path: target.display().to_string(),
            content,
        })?
    );
    Ok(())
}

async fn read_file(args: FileReadArgs) -> anyhow::Result<()> {
    let target = confine_to_workspace(&args.workspace_root, &args.path).await?;

    let metadata = tokio::fs::symlink_metadata(&target)
        .await
        .with_context(|| format!("failed to stat {}", target.display()))?;
    if !metadata.is_file() {
        bail!("refusing to read non-regular file at {}", target.display());
    }
    if metadata.len() > args.max_bytes {
        bail!(
            "refusing to read {} bytes: exceeds max-bytes limit of {}",
            metadata.len(),
            args.max_bytes
        );
    }

    let content = tokio::fs::read(&target).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&AgentFileReadResponse {
            path: target.display().to_string(),
            content,
        })?
    );
    Ok(())
}

/// Normalizes a path that is expected to be relative to a workspace root, rejecting any `..`
/// or absolute component so the result cannot lexically escape the root.
fn normalize_workspace_relative(path: &Path) -> anyhow::Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                bail!("path must not contain '..' components");
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                bail!("path must be relative to the workspace root, or nested under it");
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        bail!("path must not be empty");
    }
    Ok(normalized)
}

/// Resolves `requested` against `workspace_root`, confining the result to that root.
///
/// Rejects `..` components, absolute paths outside the root, and symlinks (at any ancestor,
/// or at the target itself) that would otherwise let the resolved path escape the root once
/// the filesystem follows them.
async fn confine_to_workspace(workspace_root: &Path, requested: &Path) -> anyhow::Result<PathBuf> {
    let canonical_root = tokio::fs::canonicalize(workspace_root)
        .await
        .with_context(|| {
            format!(
                "workspace root {} is not accessible",
                workspace_root.display()
            )
        })?;

    let relative: &Path = if requested.is_absolute() {
        requested
            .strip_prefix(workspace_root)
            .or_else(|_| requested.strip_prefix(&canonical_root))
            .map_err(|_| {
                anyhow::anyhow!(
                    "path {} is outside workspace root {}",
                    requested.display(),
                    canonical_root.display()
                )
            })?
    } else {
        requested
    };

    let normalized = normalize_workspace_relative(relative)?;
    let joined = canonical_root.join(&normalized);

    // Walk up to the nearest ancestor that already exists on disk and canonicalize it, to
    // catch a symlink planted at any intermediate directory (or at the target itself) that
    // would otherwise let the join above resolve outside the workspace root.
    let mut probe = joined.clone();
    let existing_ancestor = loop {
        if tokio::fs::try_exists(&probe).await.unwrap_or(false) {
            break probe;
        }
        match probe.parent() {
            Some(parent) if parent != probe => probe = parent.to_path_buf(),
            _ => break canonical_root.clone(),
        }
    };
    let canonical_ancestor = tokio::fs::canonicalize(&existing_ancestor)
        .await
        .with_context(|| format!("failed to canonicalize {}", existing_ancestor.display()))?;
    if !canonical_ancestor.starts_with(&canonical_root) {
        bail!(
            "path {} escapes workspace root {} via a symlink",
            requested.display(),
            canonical_root.display()
        );
    }

    Ok(joined)
}

async fn claim_lease(
    client: &reqwest::Client,
    api: &str,
    worker_id: Uuid,
    lease_seconds: Option<u64>,
) -> Result<ClaimLeaseResponse, AgentRequestError> {
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
    max_captured_output_bytes: u64,
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
        return decode_json(response).await.map_err(Into::into);
    }

    let request = agent_request_from_payload(&lease.job.payload)?;
    match execute_streaming(
        request,
        Some(client),
        Some(api),
        Some(lease.id),
        max_captured_output_bytes,
    )
    .await
    {
        Ok(result) if result.exit_code.unwrap_or(1) == 0 => {
            let response = client
                .post(format!("{api}/leases/{}/complete", lease.id))
                .json(&CompleteLeaseRequest {
                    result: Some(WorkerJobResult::RunCommand { result }),
                })
                .send()
                .await?;
            decode_json(response).await.map_err(Into::into)
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
            decode_json(response).await.map_err(Into::into)
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
            decode_json(response).await.map_err(Into::into)
        }
    }
}

async fn execute_streaming(
    request: AgentCommandRequest,
    client: Option<&reqwest::Client>,
    api: Option<&str>,
    lease_id: Option<LeaseId>,
    max_captured_output_bytes: u64,
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
        max_captured_output_bytes,
    ));
    let stderr_task = tokio::spawn(stream_reader(
        stderr,
        CommandOutputStream::Stderr,
        client.cloned(),
        api.map(ToOwned::to_owned),
        lease_id,
        max_captured_output_bytes,
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
    max_captured_bytes: u64,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut captured = Vec::new();
    let mut captured_truncated = false;
    let mut stream_decoder = Utf8StreamDecoder::default();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let chunk = &buffer[..count];
        // Cap the local copy used to build the final JSON result. The full chunk is still
        // streamed to the API (and to our own stdout/stderr) below regardless of this cap;
        // only the in-memory `captured` buffer is bounded, so a chatty or huge command can no
        // longer OOM the agent.
        if !captured_truncated {
            let remaining = max_captured_bytes.saturating_sub(captured.len() as u64);
            let take = remaining.min(chunk.len() as u64) as usize;
            captured.extend_from_slice(&chunk[..take]);
            if take < chunk.len() {
                captured_truncated = true;
                captured.extend_from_slice(
                    format!(
                        "\n[sandboxwich-agent: {stream:?} truncated after {max_captured_bytes} bytes]\n"
                    )
                    .as_bytes(),
                );
            }
        }
        match stream {
            CommandOutputStream::Stdout => tokio::io::stdout().write_all(chunk).await?,
            CommandOutputStream::Stderr => tokio::io::stderr().write_all(chunk).await?,
        }
        if let (Some(client), Some(api), Some(lease_id)) = (&client, &api, lease_id) {
            let decoded_chunk = stream_decoder.push(chunk);
            if let Err(error) =
                append_output_chunk(client, api, lease_id, stream.clone(), decoded_chunk).await
            {
                let warning =
                    format!("sandboxwich-agent: failed to stream output chunk: {error}\n");
                let _ = tokio::io::stderr().write_all(warning.as_bytes()).await;
            }
        }
    }
    if let (Some(client), Some(api), Some(lease_id)) = (&client, &api, lease_id) {
        if let Err(error) =
            append_output_chunk(client, api, lease_id, stream, stream_decoder.finish()).await
        {
            let warning = format!("sandboxwich-agent: failed to flush output chunk: {error}\n");
            let _ = tokio::io::stderr().write_all(warning.as_bytes()).await;
        }
    }
    Ok(captured)
}

#[derive(Default)]
struct Utf8StreamDecoder {
    pending: Vec<u8>,
}

impl Utf8StreamDecoder {
    fn push(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        let mut output = String::new();

        loop {
            match std::str::from_utf8(&self.pending) {
                Ok(text) => {
                    output.push_str(text);
                    self.pending.clear();
                    break;
                }
                Err(error) => {
                    let valid_up_to = error.valid_up_to();
                    if valid_up_to > 0 {
                        let text = std::str::from_utf8(&self.pending[..valid_up_to])
                            .expect("valid_up_to prefix must be valid UTF-8");
                        output.push_str(text);
                    }

                    if let Some(error_len) = error.error_len() {
                        output.push_str(
                            &String::from_utf8_lossy(
                                &self.pending[valid_up_to..valid_up_to + error_len],
                            )
                            .into_owned(),
                        );
                        self.pending.drain(..valid_up_to + error_len);
                        continue;
                    }

                    self.pending = self.pending[valid_up_to..].to_vec();
                    break;
                }
            }
        }

        output
    }

    fn finish(&mut self) -> String {
        let output = String::from_utf8_lossy(&self.pending).into_owned();
        self.pending.clear();
        output
    }
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
) -> Result<(), AgentRequestError> {
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

async fn decode_json<T>(response: reqwest::Response) -> Result<T, AgentRequestError>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(AgentRequestError::Status { status, body });
    }
    serde_json::from_str(&body).map_err(AgentRequestError::Decode)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_stream_decoder_preserves_split_multibyte_characters() {
        let mut decoder = Utf8StreamDecoder::default();

        assert_eq!(decoder.push("snow: ".as_bytes()), "snow: ");
        assert_eq!(decoder.push(&[0xE2, 0x98]), "");
        assert_eq!(decoder.push(&[0x83, b'\n']), "☃\n");
        assert_eq!(decoder.finish(), "");
    }

    #[test]
    fn utf8_stream_decoder_flushes_incomplete_suffix_lossily() {
        let mut decoder = Utf8StreamDecoder::default();

        assert_eq!(decoder.push(b"prefix "), "prefix ");
        assert_eq!(decoder.push(&[0xF0, 0x9F]), "");
        assert_eq!(decoder.finish(), "\u{FFFD}");
    }

    #[test]
    fn utf8_stream_decoder_recovers_after_invalid_bytes() {
        let mut decoder = Utf8StreamDecoder::default();

        assert_eq!(decoder.push(&[b'a', 0xFF, b'b']), "a\u{FFFD}b");
        assert_eq!(decoder.push(&[0xF0, 0x9F]), "");
        assert_eq!(decoder.push(&[0x8D, 0x95]), "🍕");
        assert_eq!(decoder.finish(), "");
    }

    #[test]
    fn heartbeat_failure_budget_trips_after_threshold() {
        let mut budget = HeartbeatFailureBudget::new(3);

        assert!(!budget.record_failure());
        assert_eq!(budget.consecutive_failures(), 1);
        assert!(!budget.record_failure());
        assert_eq!(budget.consecutive_failures(), 2);
        assert!(budget.record_failure());
        assert_eq!(budget.consecutive_failures(), 3);
    }

    #[test]
    fn heartbeat_failure_budget_resets_after_success() {
        let mut budget = HeartbeatFailureBudget::new(2);

        assert!(!budget.record_failure());
        budget.record_success();
        assert_eq!(budget.consecutive_failures(), 0);
        assert!(!budget.record_failure());
        assert!(budget.record_failure());
    }

    #[test]
    fn heartbeat_failure_budget_requires_at_least_one_failure() {
        let mut budget = HeartbeatFailureBudget::new(0);

        assert_eq!(budget.max_consecutive_failures(), 1);
        assert!(budget.record_failure());
    }

    /// A throwaway directory under the OS temp dir, removed when dropped.
    struct TempWorkspace {
        root: PathBuf,
    }

    impl TempWorkspace {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("sandboxwich-agent-test-{}", Uuid::now_v7()));
            std::fs::create_dir_all(&root).expect("failed to create temp workspace");
            Self { root }
        }

        fn path(&self) -> &Path {
            &self.root
        }
    }

    impl Drop for TempWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    async fn confine_to_workspace_rejects_dot_dot_traversal() {
        let workspace = TempWorkspace::new();

        let result = confine_to_workspace(workspace.path(), Path::new("../escape.txt")).await;

        assert!(result.is_err(), "'..' traversal should be rejected");
    }

    #[tokio::test]
    async fn confine_to_workspace_rejects_absolute_path_outside_root() {
        let workspace = TempWorkspace::new();

        let result = confine_to_workspace(workspace.path(), Path::new("/etc/passwd")).await;

        assert!(
            result.is_err(),
            "an absolute path outside the workspace root should be rejected"
        );
    }

    #[tokio::test]
    async fn confine_to_workspace_rejects_symlink_escape() {
        let workspace = TempWorkspace::new();
        let outside = TempWorkspace::new();
        let link_path = workspace.path().join("escape-link");
        std::os::unix::fs::symlink(outside.path(), &link_path).expect("failed to create symlink");

        let result =
            confine_to_workspace(workspace.path(), Path::new("escape-link/payload.txt")).await;

        assert!(
            result.is_err(),
            "a symlink planted inside the workspace that points outside it should be rejected"
        );
    }

    #[tokio::test]
    async fn confine_to_workspace_allows_nested_relative_path() {
        let workspace = TempWorkspace::new();

        let resolved = confine_to_workspace(workspace.path(), Path::new("nested/file.txt"))
            .await
            .expect("a plain nested relative path should resolve inside the workspace root");

        let canonical_root = tokio::fs::canonicalize(workspace.path()).await.unwrap();
        assert!(resolved.starts_with(&canonical_root));
        assert_eq!(resolved.file_name().unwrap(), "file.txt");
    }

    #[tokio::test]
    async fn write_file_rejects_content_exceeding_max_bytes() {
        let workspace = TempWorkspace::new();
        let target = workspace.path().join("big.txt");

        let error = write_file(FileWriteArgs {
            path: target.clone(),
            content: Some("x".repeat(16)),
            workspace_root: workspace.path().to_path_buf(),
            max_bytes: 8,
        })
        .await
        .expect_err("a write exceeding max-bytes should be rejected");

        assert!(error.to_string().contains("exceeds max-bytes"));
        assert!(
            !target.exists(),
            "the oversized write must not land on disk"
        );
    }

    #[tokio::test]
    async fn read_file_rejects_file_exceeding_max_bytes() {
        let workspace = TempWorkspace::new();
        let target = workspace.path().join("big.txt");
        tokio::fs::write(&target, "x".repeat(16)).await.unwrap();

        let error = read_file(FileReadArgs {
            path: target.clone(),
            workspace_root: workspace.path().to_path_buf(),
            max_bytes: 8,
        })
        .await
        .expect_err("a read exceeding max-bytes should be rejected");

        assert!(error.to_string().contains("exceeds max-bytes"));
    }

    #[tokio::test]
    async fn write_file_refuses_non_regular_file_target() {
        let workspace = TempWorkspace::new();
        let target = workspace.path().join("a-directory");
        tokio::fs::create_dir_all(&target).await.unwrap();

        let error = write_file(FileWriteArgs {
            path: target.clone(),
            content: Some("payload".to_string()),
            workspace_root: workspace.path().to_path_buf(),
            max_bytes: DEFAULT_MAX_FILE_BYTES,
        })
        .await
        .expect_err("writing through an existing directory should be rejected");

        assert!(error.to_string().contains("non-regular file"));
    }

    #[tokio::test]
    async fn stream_reader_truncates_captured_buffer_but_keeps_reading_to_eof() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let payload = vec![b'a'; 10];
        let write_task = tokio::spawn(async move {
            writer.write_all(&payload).await.unwrap();
            // Dropping `writer` here closes the duplex stream so the reader observes EOF.
        });

        let captured = stream_reader(reader, CommandOutputStream::Stdout, None, None, None, 4)
            .await
            .expect("stream_reader should not fail even when the cap is exceeded");

        write_task.await.unwrap();

        let captured_text = String::from_utf8_lossy(&captured);
        assert!(captured_text.starts_with("aaaa"));
        assert!(
            captured_text.contains("truncated"),
            "truncated output should carry a clear marker, got: {captured_text:?}"
        );
        assert!(
            captured.len() < 200,
            "captured buffer should stay small even though only 10 bytes were sent, got {} bytes",
            captured.len()
        );
    }
}
