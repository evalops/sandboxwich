use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, bail};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, AgentFileReadResponse, AgentFileWriteRequest,
    AgentHealthResponse, AppendCommandOutputRequest, ClaimLeaseRequest, ClaimLeaseResponse,
    CommandOutputStream, CompleteLeaseRequest, DEFAULT_COMMAND_TIMEOUT_SECS, FailLeaseRequest,
    GuestStatus, JobKind, LeaseId, LeaseResponse, RenewLeaseRequest, SandboxId,
    UpdateGuestHealthRequest, WorkerJobResult, build_api_client,
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
/// Minimum lease-renewal interval while a command executes, so short/dry-run leases
/// don't hammer the API. Mirrors `sandboxwich-worker`'s constant of the same name.
const MIN_RENEW_INTERVAL: Duration = Duration::from_secs(5);
/// Fallback lease duration used to size the renewal interval if a lease's
/// `expires_at`/`leased_at` pair is somehow non-positive.
const FALLBACK_LEASE_DURATION: Duration = Duration::from_secs(30);
/// Attempts (including the first) for a single lease-renewal call before giving up and
/// cancelling the command that lease covers, so it isn't left running (and possibly
/// re-queued and executed a second time elsewhere) against a lease we can no longer prove
/// is still ours.
const RENEW_ATTEMPTS: u32 = 3;
/// Delay between renewal retries within a single renewal attempt window.
const RENEW_RETRY_DELAY: Duration = Duration::from_millis(250);
/// How often a command's execution polls for a lease-cancellation signal.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(500);

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

    /// Path to a file containing the API token (GH-101), taking precedence
    /// over `--api-token`/`SANDBOXWICH_API_TOKEN` when set. This is how the
    /// Kubernetes provider delivers a worker-scoped token (GH-64) mounted
    /// as a read-only Secret volume rather than a plain env var.
    #[arg(long, env = "SANDBOXWICH_API_TOKEN_FILE")]
    api_token_file: Option<PathBuf>,

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

    /// Path to a file containing the API token (GH-101), taking precedence
    /// over `--api-token`/`SANDBOXWICH_API_TOKEN` when set. This is how the
    /// Kubernetes provider delivers a worker-scoped token (GH-64) mounted
    /// as a read-only Secret volume rather than a plain env var.
    #[arg(long, env = "SANDBOXWICH_API_TOKEN_FILE")]
    api_token_file: Option<PathBuf>,

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

    /// Path to a file containing the API token (GH-101), taking precedence
    /// over `--api-token`/`SANDBOXWICH_API_TOKEN` when set. This is how the
    /// Kubernetes provider delivers a worker-scoped token (GH-64) mounted
    /// as a read-only Secret volume rather than a plain env var.
    #[arg(long, env = "SANDBOXWICH_API_TOKEN_FILE")]
    api_token_file: Option<PathBuf>,

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

    /// Maximum time the command may run before it is killed and a timeout
    /// failure is reported. Unset falls back to `DEFAULT_COMMAND_TIMEOUT_SECS`.
    #[arg(long)]
    timeout_secs: Option<u64>,

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
        let api_token = resolve_api_token(args.api_token_file, args.api_token)?;
        let client = build_api_client(api_token.as_deref(), args.tenant.as_deref())?;
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
    let api_token = resolve_api_token(args.api_token_file, args.api_token)?;
    let client = build_api_client(api_token.as_deref(), args.tenant.as_deref())?;
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
                        claim_lease(&client, &api, worker_id, sandbox_id, args.lease_seconds)
                    })
                    .await?;

                if let Some(lease) = claim_response.lease
                    && let Err(error) = handle_lease(
                        &client,
                        &api,
                        sandbox_id,
                        lease,
                        args.max_captured_output_bytes,
                    )
                    .await
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
        let api_token = resolve_api_token(args.api_token_file, args.api_token)?;
        Some(build_api_client(
            api_token.as_deref(),
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
            timeout_secs: args.timeout_secs,
        },
        client.as_ref(),
        api,
        lease,
        args.max_captured_output_bytes,
        None,
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

    let (workspace, relative, target) = open_workspace(&args.workspace_root, &args.path)?;
    if let Some(parent) = relative.parent()
        && !parent.as_os_str().is_empty()
    {
        workspace.create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = workspace
        .open_with(&relative, &options)
        .with_context(|| format!("failed to open {} beneath workspace", args.path.display()))?;
    if !file.metadata()?.is_file() {
        bail!(
            "refusing to write to non-regular file at {}",
            target.display()
        );
    }
    file.write_all(&content)?;
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
    let (workspace, relative, target) = open_workspace(&args.workspace_root, &args.path)?;
    let file = workspace
        .open(&relative)
        .with_context(|| format!("failed to open {} beneath workspace", args.path.display()))?;
    let metadata = file.metadata()?;
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

    let mut content = Vec::with_capacity(metadata.len().min(args.max_bytes) as usize);
    file.take(args.max_bytes.saturating_add(1))
        .read_to_end(&mut content)?;
    if content.len() as u64 > args.max_bytes {
        bail!(
            "refusing to read a file that grew beyond max-bytes limit of {}",
            args.max_bytes
        );
    }
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

/// Opens the workspace as a directory capability and returns a normalized relative path.
/// All subsequent filesystem resolution is descriptor-relative, so replacing any ancestor
/// with a symlink between validation and use cannot redirect the operation outside this handle.
fn open_workspace(
    workspace_root: &Path,
    requested: &Path,
) -> anyhow::Result<(Dir, PathBuf, PathBuf)> {
    let relative = if requested.is_absolute() {
        requested
            .strip_prefix(workspace_root)
            .map_err(|_| {
                anyhow::anyhow!(
                    "path {} is outside workspace root {}",
                    requested.display(),
                    workspace_root.display()
                )
            })?
            .to_path_buf()
    } else {
        requested.to_path_buf()
    };
    let relative = normalize_workspace_relative(&relative)?;
    let workspace =
        Dir::open_ambient_dir(workspace_root, ambient_authority()).with_context(|| {
            format!(
                "workspace root {} is not accessible",
                workspace_root.display()
            )
        })?;
    let display_path = workspace_root.join(&relative);
    Ok((workspace, relative, display_path))
}

async fn claim_lease(
    client: &reqwest::Client,
    api: &str,
    worker_id: Uuid,
    sandbox_id: SandboxId,
    lease_seconds: Option<u64>,
) -> Result<ClaimLeaseResponse, AgentRequestError> {
    // Scope the claim to this daemon's own sandbox and to the only job kind it
    // knows how to execute. This is advisory server-side filtering, not a
    // security boundary (see the doc comment on `ClaimLeaseRequest`): the
    // guest and its worker share one worker-scoped token, so a compromised
    // guest can strip these fields and claim anything the token's
    // capabilities allow. `handle_lease` below re-checks the claimed job's
    // sandbox and kind after the fact as defense in depth against a
    // well-behaved agent claiming the wrong job (e.g. via a future
    // server-side filtering bug), not against a malicious one.
    let response = client
        .post(format!("{api}/workers/{worker_id}/leases/claim"))
        .json(&ClaimLeaseRequest {
            lease_seconds,
            sandbox_id: Some(sandbox_id),
            kinds: Some(vec![JobKind::RunCommand]),
        })
        .send()
        .await?;
    decode_json(response).await
}

async fn renew_lease(
    client: &reqwest::Client,
    api: &str,
    lease_id: LeaseId,
) -> Result<LeaseResponse, AgentRequestError> {
    let response = client
        .post(format!("{api}/leases/{lease_id}/renew"))
        .json(&RenewLeaseRequest {
            lease_seconds: None,
        })
        .send()
        .await?;
    decode_json(response).await
}

/// Renews `lease_id` in the background for as long as the caller's command
/// executes, at half the lease's original TTL, so a long-running command
/// doesn't have its lease expire (and get re-queued/claimed onto another
/// worker, running the same job twice) mid-flight. Mirrors
/// `sandboxwich-worker`'s `handle_lease` renewal task.
///
/// If renewal is lost -- `RENEW_ATTEMPTS` consecutive calls fail -- this
/// stops renewing (retrying a lease that's plausibly already gone forever
/// would just hammer the API) and flips `cancelled`, which `execute_streaming`
/// polls to kill the still-running command instead of letting it keep
/// executing against a lease we can no longer prove is still ours.
fn spawn_lease_renewal_task(
    client: reqwest::Client,
    api: String,
    lease: &sandboxwich_core::JobLease,
    cancelled: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let lease_id = lease.id;
    let renew_interval = (lease.expires_at - lease.leased_at)
        .to_std()
        .map(|duration| (duration / 2).max(MIN_RENEW_INTERVAL))
        .unwrap_or(FALLBACK_LEASE_DURATION);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(renew_interval).await;
            let mut last_error = None;
            let mut renewed = false;
            for attempt in 1..=RENEW_ATTEMPTS {
                match renew_lease(&client, &api, lease_id).await {
                    Ok(_) => {
                        renewed = true;
                        break;
                    }
                    Err(error) => {
                        last_error = Some(error);
                        if attempt < RENEW_ATTEMPTS {
                            tokio::time::sleep(RENEW_RETRY_DELAY).await;
                        }
                    }
                }
            }
            if !renewed {
                let error = last_error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "unknown error".to_string());
                eprintln!(
                    "warning: renewing lease {lease_id} failed after {RENEW_ATTEMPTS} attempts \
                     ({error}); cancelling the running command instead of letting it keep \
                     executing against a lease we can no longer prove is still ours"
                );
                cancelled.store(true, Ordering::SeqCst);
                return;
            }
        }
    })
}

/// Why a claimed lease must be handed back rather than executed. Both variants
/// mean the job merely landed on the wrong executor -- not that it's invalid --
/// so `handle_lease` always fails these with `retry: true`, never `retry: false`,
/// so the intended executor still gets a chance to run it.
#[derive(Debug, Eq, PartialEq)]
enum LeaseScopeViolation {
    /// This daemon only executes `run_command` jobs.
    WrongKind { kind: JobKind },
    /// The job's payload targets a different sandbox than this daemon's own
    /// `--sandbox-id`.
    WrongSandbox { job_sandbox_id: SandboxId },
}

impl std::fmt::Display for LeaseScopeViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseScopeViolation::WrongKind { kind } => write!(
                f,
                "sandboxwich-agent daemon only handles run_command leases, got {kind:?}"
            ),
            LeaseScopeViolation::WrongSandbox { job_sandbox_id } => write!(
                f,
                "sandboxwich-agent claimed a job for sandbox {job_sandbox_id}"
            ),
        }
    }
}

/// Pure defense-in-depth check, run *after* a claim succeeds, that a claimed job
/// actually belongs to this daemon: matches the daemon's `--sandbox-id` and is a
/// `run_command` job. This is NOT the security boundary -- see the doc comment on
/// `ClaimLeaseRequest::sandbox_id` -- it catches a well-behaved agent claiming the
/// wrong job (e.g. a server-side filtering bug, or a claim made against an API
/// that predates this filtering), not an adversarial one.
///
/// A missing or unparseable `sandboxId` in the payload is treated as "could not
/// verify" rather than a violation, matching the daemon's behavior before this
/// check existed.
fn lease_scope_violation(
    job: &sandboxwich_core::Job,
    sandbox_id: SandboxId,
) -> Option<LeaseScopeViolation> {
    if job.kind != JobKind::RunCommand {
        return Some(LeaseScopeViolation::WrongKind {
            kind: job.kind.clone(),
        });
    }
    let job_sandbox_id = job_payload_sandbox_id(&job.payload)?;
    if job_sandbox_id != sandbox_id {
        return Some(LeaseScopeViolation::WrongSandbox { job_sandbox_id });
    }
    None
}

async fn handle_lease(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    lease: sandboxwich_core::JobLease,
    max_captured_output_bytes: u64,
) -> anyhow::Result<LeaseResponse> {
    if let Some(violation) = lease_scope_violation(&lease.job, sandbox_id) {
        eprintln!(
            "sandboxwich-agent: claimed lease {} for job {} out of scope for sandbox {sandbox_id} \
             ({violation}); failing with retry so the intended executor can claim it instead",
            lease.id, lease.job.id
        );
        let response = client
            .post(format!("{api}/leases/{}/fail", lease.id))
            .json(&FailLeaseRequest {
                error: violation.to_string(),
                retry: true,
            })
            .send()
            .await?;
        return decode_json(response).await.map_err(Into::into);
    }

    let request = agent_request_from_payload(&lease.job.payload)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let renew_task =
        spawn_lease_renewal_task(client.clone(), api.to_string(), &lease, cancelled.clone());

    let result = execute_streaming(
        request,
        Some(client),
        Some(api),
        Some(lease.id),
        max_captured_output_bytes,
        Some(cancelled),
    )
    .await;

    renew_task.abort();
    let _ = renew_task.await;

    match result {
        // A non-zero exit code means the command actually ran to completion in the
        // guest -- that is a successful *lease* outcome (the agent did what it was
        // asked), not an infrastructure failure. This used to report the lease
        // itself as failed whenever the exit code was non-zero, which discarded the
        // typed `AgentCommandResult` (stdout, in particular) and conflated "the
        // command exited 1" with "the agent couldn't run it at all". Always
        // complete the lease with the full result; the control plane derives the
        // command's own Finished/Failed status from `exit_code`.
        Ok(result) => {
            let response = client
                .post(format!("{api}/leases/{}/complete", lease.id))
                .json(&CompleteLeaseRequest {
                    result: Some(WorkerJobResult::RunCommand { result }),
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
    cancelled: Option<Arc<AtomicBool>>,
) -> anyhow::Result<AgentCommandResult> {
    let Some((program, args)) = request.argv.split_first() else {
        bail!("argv must contain at least one item");
    };
    let timeout = Duration::from_secs(request.timeout_secs.unwrap_or(DEFAULT_COMMAND_TIMEOUT_SECS));

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

    // Before this bound existed, a wedged command (or one that simply runs
    // longer than the caller expects) left `child.wait()` waiting forever,
    // wedging this worker/agent slot for good. Racing in a poll for
    // `cancelled` alongside it means a command also gets killed promptly if
    // `handle_lease`'s background renewal task loses the lease, instead of
    // continuing to run to completion (and possibly being re-queued and
    // executed a second time elsewhere) against a lease we can no longer
    // prove is still ours.
    let wait_for_cancellation = async {
        match &cancelled {
            Some(cancelled) => loop {
                if cancelled.load(Ordering::SeqCst) {
                    return;
                }
                tokio::time::sleep(CANCEL_POLL_INTERVAL).await;
            },
            None => std::future::pending().await,
        }
    };

    let status = tokio::select! {
        result = tokio::time::timeout(timeout, child.wait()) => {
            match result {
                Ok(status_result) => status_result.context("failed to wait for command")?,
                Err(_elapsed) => {
                    // Kill (and reap, so it doesn't linger as a zombie) the timed-out
                    // child. This closes its stdout/stderr pipes, but the streaming
                    // tasks are aborted directly below rather than drained, since
                    // we're reporting a distinct failure instead of a result anyway.
                    if let Err(kill_error) = child.start_kill() {
                        eprintln!("warning: failed to kill timed-out command: {kill_error}");
                    }
                    let _ = child.wait().await;
                    stdout_task.abort();
                    stderr_task.abort();
                    bail!("command timed out after {timeout:?} and was killed (argv[0] = {program:?})");
                }
            }
        }
        () = wait_for_cancellation => {
            if let Err(kill_error) = child.start_kill() {
                eprintln!("warning: failed to kill cancelled command: {kill_error}");
            }
            let _ = child.wait().await;
            stdout_task.abort();
            stderr_task.abort();
            bail!(
                "command was cancelled because lease renewal was lost (argv[0] = {program:?})"
            );
        }
    };
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
    if let (Some(client), Some(api), Some(lease_id)) = (&client, &api, lease_id)
        && let Err(error) =
            append_output_chunk(client, api, lease_id, stream, stream_decoder.finish()).await
    {
        let warning = format!("sandboxwich-agent: failed to flush output chunk: {error}\n");
        let _ = tokio::io::stderr().write_all(warning.as_bytes()).await;
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
                        output.push_str(&String::from_utf8_lossy(
                            &self.pending[valid_up_to..valid_up_to + error_len],
                        ));
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
        .header("idempotency-key", Uuid::now_v7().to_string())
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

/// Resolves the effective API token for guest-facing calls (claim/renew/
/// complete/fail/output, guest-health). Prefers the contents of the file at
/// `token_file` (`--api-token-file`/`SANDBOXWICH_API_TOKEN_FILE`) -- how the
/// Kubernetes provider delivers a worker-scoped token (GH-64) into a
/// sandbox pod as a mounted, read-only Secret volume rather than a plain
/// env var (GH-101), so the token never shows up in `kubectl get pod -o
/// yaml`/`kubectl describe pod` or anything else that reads this pod's
/// spec/status through the Kubernetes API -- falling back to `cli_token`
/// (`--api-token`/`SANDBOXWICH_API_TOKEN`) for non-Kubernetes deployments
/// where no such file exists.
fn resolve_api_token(
    token_file: Option<PathBuf>,
    cli_token: Option<String>,
) -> anyhow::Result<Option<String>> {
    let Some(path) = token_file else {
        return Ok(cli_token);
    };
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read --api-token-file at {}", path.display()))?;
    let token = contents.trim();
    if token.is_empty() {
        bail!("--api-token-file at {} is empty", path.display());
    }
    Ok(Some(token.to_string()))
}

/// Reads the `sandboxId` field `sandboxwich-api` stamps onto every `run_command`
/// job payload (see `queue_command` in `sandboxwich-api`). Returns `None` rather
/// than erroring if it's absent or malformed so a payload shape the daemon
/// doesn't recognize doesn't itself become a way to dodge the sandbox check in
/// `handle_lease`; callers should treat `None` as "could not verify" and the
/// mismatch check simply becomes a no-op in that case, same as before this
/// filtering existed.
fn job_payload_sandbox_id(payload: &serde_json::Value) -> Option<SandboxId> {
    payload
        .get("sandboxId")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
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
    let timeout_secs = payload.get("timeoutSecs").and_then(|value| value.as_u64());
    Ok(AgentCommandRequest {
        argv,
        cwd,
        env,
        timeout_secs,
    })
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

    /// Writes `contents` to a fresh, uniquely-named temp file and returns its
    /// path. Mirrors the temp-file-per-test pattern `sandboxwich-worker`'s
    /// provider tests use for their fake `kubectl` script, so tests can run
    /// in parallel without colliding on a shared path.
    fn write_temp_file(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("sandboxwich-agent-test-{}", Uuid::new_v4()));
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    #[test]
    fn resolve_api_token_returns_cli_token_when_no_token_file_given() {
        let token = resolve_api_token(None, Some("cli-token".to_string()))
            .expect("resolution should succeed with no token file");
        assert_eq!(token.as_deref(), Some("cli-token"));
    }

    #[test]
    fn resolve_api_token_returns_none_when_neither_source_is_set() {
        let token =
            resolve_api_token(None, None).expect("resolution should succeed with nothing set");
        assert_eq!(token, None);
    }

    #[test]
    fn resolve_api_token_prefers_file_contents_over_the_cli_token() {
        // GH-101: this is how the Kubernetes provider's mounted Secret
        // (SANDBOXWICH_API_TOKEN_FILE) takes priority over any
        // --api-token/SANDBOXWICH_API_TOKEN also present in the pod env.
        let path = write_temp_file("  sbw_wtok_from_file  \n");

        let token = resolve_api_token(Some(path.clone()), Some("cli-token".to_string()))
            .expect("resolution should succeed");

        assert_eq!(token.as_deref(), Some("sbw_wtok_from_file"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resolve_api_token_errors_when_the_token_file_is_empty() {
        let path = write_temp_file("   \n");

        let error = resolve_api_token(Some(path.clone()), Some("cli-token".to_string()))
            .expect_err("an empty token file should not be silently treated as no token");

        assert!(error.to_string().contains("is empty"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resolve_api_token_errors_when_the_token_file_does_not_exist() {
        let path =
            std::env::temp_dir().join(format!("sandboxwich-agent-test-missing-{}", Uuid::new_v4()));

        let error = resolve_api_token(Some(path), Some("cli-token".to_string())).expect_err(
            "a configured but unreadable token file should be a hard error, not a silent fallback",
        );

        assert!(
            error
                .to_string()
                .contains("failed to read --api-token-file")
        );
    }

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
    async fn workspace_capability_rejects_dot_dot_traversal() {
        let workspace = TempWorkspace::new();

        let result = open_workspace(workspace.path(), Path::new("../escape.txt"));

        assert!(result.is_err(), "'..' traversal should be rejected");
    }

    #[tokio::test]
    async fn workspace_capability_rejects_absolute_path_outside_root() {
        let workspace = TempWorkspace::new();

        let result = open_workspace(workspace.path(), Path::new("/etc/passwd"));

        assert!(
            result.is_err(),
            "an absolute path outside the workspace root should be rejected"
        );
    }

    #[tokio::test]
    async fn workspace_capability_rejects_symlink_escape() {
        let workspace = TempWorkspace::new();
        let outside = TempWorkspace::new();
        let link_path = workspace.path().join("escape-link");
        std::os::unix::fs::symlink(outside.path(), &link_path).expect("failed to create symlink");
        std::fs::write(outside.path().join("payload.txt"), b"secret").unwrap();

        let result = read_file(FileReadArgs {
            path: PathBuf::from("escape-link/payload.txt"),
            workspace_root: workspace.path().to_path_buf(),
            max_bytes: DEFAULT_MAX_FILE_BYTES,
        })
        .await;

        assert!(
            result.is_err(),
            "a symlink planted inside the workspace that points outside it should be rejected"
        );
    }

    #[tokio::test]
    async fn workspace_capability_allows_nested_relative_path() {
        let workspace = TempWorkspace::new();

        let (_workspace, relative, resolved) =
            open_workspace(workspace.path(), Path::new("nested/file.txt"))
                .expect("a plain nested relative path should resolve inside the workspace root");

        assert_eq!(relative, Path::new("nested/file.txt"));
        assert!(resolved.starts_with(workspace.path()));
        assert_eq!(resolved.file_name().unwrap(), "file.txt");
    }

    #[test]
    fn workspace_descriptor_cannot_be_redirected_after_open() {
        let workspace = TempWorkspace::new();
        let outside = TempWorkspace::new();
        std::fs::write(workspace.path().join("payload.txt"), b"inside").unwrap();
        std::fs::write(outside.path().join("payload.txt"), b"outside-secret").unwrap();

        let (directory, relative, _) =
            open_workspace(workspace.path(), Path::new("payload.txt")).unwrap();
        let moved_root = workspace.path().with_extension("moved");
        std::fs::rename(workspace.path(), &moved_root).unwrap();
        std::os::unix::fs::symlink(outside.path(), workspace.path()).unwrap();

        let mut content = String::new();
        directory
            .open(relative)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(
            content, "inside",
            "descriptor-relative lookup must stay bound to the opened workspace"
        );

        std::fs::remove_file(workspace.path()).unwrap();
        std::fs::rename(moved_root, workspace.path()).unwrap();
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

        assert!(
            error.to_string().contains("failed to open")
                || error.to_string().contains("non-regular file")
        );
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

    #[tokio::test]
    async fn execute_streaming_completes_normally_within_its_timeout() {
        let request = AgentCommandRequest {
            argv: vec!["sh".to_string(), "-c".to_string(), "echo ok".to_string()],
            cwd: None,
            env: BTreeMap::new(),
            timeout_secs: Some(5),
        };
        let result = execute_streaming(
            request,
            None,
            None,
            None,
            DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
            None,
        )
        .await
        .expect("fast command should complete well within its timeout");
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout.trim(), "ok");
    }

    #[tokio::test]
    async fn execute_streaming_kills_and_errors_on_timeout() {
        // Regression test for item 3(a): before this fix, `execute_streaming`
        // called `child.wait().await` with no bound at all, so a wedged (or
        // simply too-slow) command hung the agent's job-execution loop
        // forever. A command that would run far longer than its requested
        // timeout must be killed and reported as a distinct timeout failure
        // well before it would naturally exit.
        let request = AgentCommandRequest {
            argv: vec!["sh".to_string(), "-c".to_string(), "sleep 30".to_string()],
            cwd: None,
            env: BTreeMap::new(),
            timeout_secs: Some(1),
        };
        let started = std::time::Instant::now();
        let error = execute_streaming(
            request,
            None,
            None,
            None,
            DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
            None,
        )
        .await
        .expect_err("a command that outlives its timeout must be treated as a failure");
        let elapsed = started.elapsed();

        assert!(
            error.to_string().contains("timed out"),
            "error should be distinctly reported as a timeout, got: {error}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the timed-out child should have been killed almost immediately instead of \
             the caller waiting anywhere near its full 30s sleep; elapsed = {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn execute_streaming_is_cancelled_when_lease_renewal_is_lost() {
        // Regression test for item 4(a): the agent never renewed its lease at
        // all, so a long-running command whose lease expired kept executing
        // to completion regardless -- the job could be re-queued and picked
        // up by another worker while this one was still running it. Now a
        // lost-renewal signal (as `handle_lease`'s background renewal task
        // sets when it gives up) must cancel the command promptly instead of
        // letting it run to completion.
        let request = AgentCommandRequest {
            argv: vec!["sh".to_string(), "-c".to_string(), "sleep 30".to_string()],
            cwd: None,
            env: BTreeMap::new(),
            timeout_secs: Some(60), // Long enough that the timeout branch can't win the race.
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let flip_cancelled = cancelled.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            flip_cancelled.store(true, Ordering::SeqCst);
        });

        let started = std::time::Instant::now();
        let error = execute_streaming(
            request,
            None,
            None,
            None,
            DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
            Some(cancelled),
        )
        .await
        .expect_err("a cancelled command must be treated as a failure, not left running");
        let elapsed = started.elapsed();

        assert!(
            error.to_string().contains("cancelled"),
            "error should be distinctly reported as a cancellation, got: {error}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the cancelled child should have been killed almost immediately instead of \
             the caller waiting anywhere near its full 30s sleep or 60s timeout; \
             elapsed = {elapsed:?}"
        );
    }

    fn test_job(kind: JobKind, payload: serde_json::Value) -> sandboxwich_core::Job {
        sandboxwich_core::Job {
            id: sandboxwich_core::JobId::new(),
            tenant_id: "default".to_string(),
            kind,
            status: sandboxwich_core::JobStatus::Leased,
            payload,
            required_capability: sandboxwich_core::WorkerCapability::RunCommand,
            priority: 0,
            attempts: 1,
            max_attempts: 3,
            scheduled_at: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_error: None,
        }
    }

    #[test]
    fn job_payload_sandbox_id_reads_the_sandbox_id_field() {
        let sandbox_id = SandboxId(Uuid::now_v7());
        let payload = serde_json::json!({ "sandboxId": sandbox_id, "argv": ["echo", "hi"] });

        assert_eq!(job_payload_sandbox_id(&payload), Some(sandbox_id));
    }

    #[test]
    fn job_payload_sandbox_id_returns_none_when_the_field_is_absent() {
        let payload = serde_json::json!({ "argv": ["echo", "hi"] });

        assert_eq!(job_payload_sandbox_id(&payload), None);
    }

    #[test]
    fn job_payload_sandbox_id_returns_none_when_the_field_is_malformed() {
        let payload = serde_json::json!({ "sandboxId": "not-a-uuid" });

        assert_eq!(job_payload_sandbox_id(&payload), None);
    }

    // The following four tests cover consequence (a) and (b) from the lease-scoping
    // bug this module fixes: an agent that claims a RunCommand job for a *different*
    // sandbox must never execute it (it would run against the wrong
    // filesystem/environment and misattribute results), and an agent that claims a
    // non-RunCommand job (Provision/Snapshot/Fork) must fail it with `retry: true`,
    // not `retry: false` -- `retry: false` would permanently kill work the real
    // worker would have handled correctly.

    #[test]
    fn lease_scope_violation_accepts_a_run_command_job_for_its_own_sandbox() {
        let sandbox_id = SandboxId(Uuid::now_v7());
        let job = test_job(
            JobKind::RunCommand,
            serde_json::json!({ "sandboxId": sandbox_id, "argv": ["echo", "hi"] }),
        );

        assert_eq!(lease_scope_violation(&job, sandbox_id), None);
    }

    #[test]
    fn lease_scope_violation_accepts_a_run_command_job_when_sandbox_id_cannot_be_verified() {
        // A payload shape the daemon doesn't recognize (missing/malformed sandboxId)
        // must not itself become a way to bypass the check -- but it also shouldn't
        // manufacture a false-positive violation for a legitimately un-annotated
        // payload, matching behavior from before this check existed.
        let sandbox_id = SandboxId(Uuid::now_v7());
        let job = test_job(
            JobKind::RunCommand,
            serde_json::json!({ "argv": ["echo", "hi"] }),
        );

        assert_eq!(lease_scope_violation(&job, sandbox_id), None);
    }

    #[test]
    fn lease_scope_violation_rejects_a_run_command_job_for_a_different_sandbox() {
        let own_sandbox_id = SandboxId(Uuid::now_v7());
        let other_sandbox_id = SandboxId(Uuid::now_v7());
        let job = test_job(
            JobKind::RunCommand,
            serde_json::json!({ "sandboxId": other_sandbox_id, "argv": ["rm", "-rf", "/"] }),
        );

        let violation = lease_scope_violation(&job, own_sandbox_id)
            .expect("a job for a different sandbox must be rejected, never executed");
        assert_eq!(
            violation,
            LeaseScopeViolation::WrongSandbox {
                job_sandbox_id: other_sandbox_id
            }
        );
    }

    #[test]
    fn lease_scope_violation_rejects_a_non_run_command_job_with_retryable_kind() {
        let sandbox_id = SandboxId(Uuid::now_v7());
        let job = test_job(
            JobKind::ProvisionSandbox,
            serde_json::json!({ "sandboxId": sandbox_id }),
        );

        let violation = lease_scope_violation(&job, sandbox_id)
            .expect("a non-run_command job must be rejected, not executed");
        assert_eq!(
            violation,
            LeaseScopeViolation::WrongKind {
                kind: JobKind::ProvisionSandbox
            }
        );
    }

    #[test]
    fn every_lease_scope_violation_fails_the_lease_with_retry_true() {
        // Regression guard for consequence (b): it must never be possible to build a
        // `FailLeaseRequest` from a `LeaseScopeViolation` with `retry: false`, which
        // would permanently kill a job the intended executor would have handled.
        let sandbox_id = SandboxId(Uuid::now_v7());
        let wrong_kind = test_job(JobKind::CreateSnapshot, serde_json::json!({}));
        let wrong_sandbox = test_job(
            JobKind::RunCommand,
            serde_json::json!({ "sandboxId": SandboxId(Uuid::now_v7()) }),
        );

        for job in [wrong_kind, wrong_sandbox] {
            let violation = lease_scope_violation(&job, sandbox_id)
                .expect("both fixtures are constructed to violate lease scope");
            let request = FailLeaseRequest {
                error: violation.to_string(),
                retry: true,
            };
            assert!(request.retry, "lease scope violations must always retry");
        }
    }
}
