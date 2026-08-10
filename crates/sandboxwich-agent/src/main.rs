#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read as _, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, put},
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use ring::signature::{ED25519, UnparsedPublicKey};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use rustls_pemfile::Item;
use sandboxwich_core::{
    AgentCommandRequest, AgentCommandResult, AgentFileReadResponse, AgentFileWriteRequest,
    AgentHealthResponse, AppendCommandOutputRequest, ClaimLeaseRequest, ClaimLeaseResponse,
    CommandOutputStream, CompleteLeaseRequest, DEFAULT_COMMAND_TIMEOUT_SECS, ErrorEnvelope,
    FailLeaseRequest, GUEST_AGENT_CAPABILITY_REPORT_CHECK, GuestAgentCapabilityReport, GuestStatus,
    GuestTokenResponse, JobKind, LeaseId, LeaseResponse, MintGuestTokenRequest,
    RefreshGuestTokenRequest, RenewLeaseRequest, ResidentProcessBootstrapReadRequest,
    ResidentProcessBootstrapReadResponse, ResidentProcessId, ResidentProcessObservationRequest,
    ResidentProcessObservedState, ResidentProcessRestartPolicy, SandboxId,
    UpdateGuestHealthRequest, ValidateSterileCellLeaseRequestV1,
    ValidateSterileCellLeaseResponseV1, WorkerJobResult, build_api_client,
    resident_process_run_as_uid, validate_agent_command_request,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command as TokioProcessCommand,
    sync::Mutex,
};
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

mod compiler_cache_archive;
mod resident_process_supervisor;

use resident_process_supervisor::{
    ResidentProcessSupervisor, ResidentProcessTaskCompletion, ResidentProcessTaskMetadata,
};

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
/// Default TTL requested when the daemon self-mints its own sandbox-scoped
/// guest token (see `resolve_guest_client`). Matches the API's own default
/// (`mint_guest_token`'s `ttl_seconds.unwrap_or(3600)`) so leaving both sides
/// at their defaults produces one consistent lifetime.
const DEFAULT_GUEST_TOKEN_TTL_SECS: u64 = 3600;
/// Refresh the guest credential at this fraction of its TTL so long-lived
/// daemons never hit a deterministic 401 after the default 3600s mint.
const GUEST_TOKEN_REFRESH_FRACTION: f64 = 0.65;
/// Initial delay for retrying a resident observation after a bootstrap has
/// been delivered. The delay uses [`Backoff`], so it remains bounded even
/// during a long control-plane outage.
const RESIDENT_OBSERVATION_RETRY_DELAY: Duration = Duration::from_millis(250);

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
    Daemon(Box<DaemonArgs>),
    /// Consume one validated sterile activation bundle and supervise Maestro.
    SterileLauncher(SterileLauncherArgs),
    /// Verify one controller-signed Agent Sandbox activation and atomically
    /// consume its nonce before tenant material is admitted.
    AgentSandboxActivate(AgentSandboxActivateArgs),
    /// Keep the post-claim generic launcher alive inside the claimed pod.
    AgentSandboxLauncher(AgentSandboxLauncherArgs),
    /// Secretless PID1 for a warm pod; waits for the post-claim bundle before
    /// entering the long-lived launcher.
    AgentSandboxPreclaim(AgentSandboxPreclaimArgs),
    Exec(ExecArgs),
    WriteFile(FileWriteArgs),
    ReadFile(FileReadArgs),
    /// Create a bounded, deterministic snapshot of the local sccache directory.
    CompilerCacheCapture(CompilerCacheCaptureArgs),
    /// Validate and atomically activate a staged compiler-cache snapshot.
    CompilerCacheRestore(CompilerCacheRestoreArgs),
    /// Establish the restricted helper workspace boundary before the workload starts.
    CompilerCachePrepareWorkspace,
    /// Hold the dedicated compiler-cache helper container open after verifying its boundary.
    CompilerCacheHelper,
    /// Stage a bounded archive at the helper's fixed private path.
    CompilerCacheStageArchive(CompilerCacheStageArchiveArgs),
}

#[derive(Debug, Args)]
struct AgentSandboxActivateArgs {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long, env = "SANDBOXWICH_AGENT_SANDBOX_PUBLIC_KEY_FILE")]
    public_key: PathBuf,
    #[arg(long, default_value = "/run/sandboxwich/activation-nonces")]
    nonce_dir: PathBuf,
    #[arg(long, env = "SANDBOXWICH_AGENT_SANDBOX_EXPECTED_CLAIM_UID")]
    expected_claim_uid: Option<String>,
    #[arg(long, env = "SANDBOXWICH_AGENT_SANDBOX_EXPECTED_SANDBOX_UID")]
    expected_sandbox_uid: Option<String>,
    #[arg(long, env = "SANDBOXWICH_AGENT_SANDBOX_EXPECTED_POD_UID")]
    expected_pod_uid: Option<String>,
    #[arg(long, env = "SANDBOXWICH_AGENT_SANDBOX_EXPECTED_IMAGE_DIGEST")]
    expected_image_digest: Option<String>,
    #[arg(long, env = "SANDBOXWICH_AGENT_SANDBOX_EXPECTED_BOOTSTRAP_DIGEST")]
    expected_bootstrap_digest: Option<String>,
    #[arg(long, env = "SANDBOXWICH_AGENT_SANDBOX_EXPECTED_POLICY_DIGEST")]
    expected_policy_digest: Option<String>,
}

#[derive(Debug, Args)]
struct AgentSandboxLauncherArgs {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long, default_value = "/run/sandboxwich/agent-sandbox-ready")]
    ready_file: PathBuf,
    #[arg(long, default_value = "/run/sandboxwich/activation.ready")]
    activation_marker: PathBuf,
}

#[derive(Debug, Args)]
struct AgentSandboxPreclaimArgs {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long, default_value = "/run/sandboxwich/agent-sandbox-ready")]
    ready_file: PathBuf,
    #[arg(long, default_value = "/run/sandboxwich/activation.ready")]
    activation_marker: PathBuf,
}

#[derive(Debug, Args)]
struct SterileLauncherArgs {
    #[arg(long, env = "SANDBOXWICH_STERILE_ACTIVATION_BIND")]
    activation_bind: SocketAddr,
    #[arg(long, env = "SANDBOXWICH_STERILE_ACTIVATION_SERVER_CERT_FILE")]
    server_cert_file: PathBuf,
    #[arg(long, env = "SANDBOXWICH_STERILE_ACTIVATION_SERVER_KEY_FILE")]
    server_key_file: PathBuf,
    #[arg(long, env = "SANDBOXWICH_STERILE_ACTIVATION_CLIENT_CA_FILE")]
    client_ca_file: PathBuf,
    #[arg(long, env = "SANDBOXWICH_STERILE_ACTIVATION_CLIENT_URI")]
    client_uri: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SterileActivationRequestV1 {
    version: u8,
    candidate: sandboxwich_core::SterilePoolCandidateV1,
    fence: sandboxwich_core::SterileResidentActivationFenceV1,
    validated_expires_at: DateTime<Utc>,
    argv: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    bootstrap: ResidentProcessBootstrapReadResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SterileLauncherStatusV1 {
    phase: SterileLauncherPhaseV1,
    pid: Option<u32>,
    exit_code: Option<i32>,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SterileLauncherPhaseV1 {
    Accepted,
    Running,
    Terminal,
}

#[derive(Clone)]
struct SterileLauncherServerState {
    activation: Arc<Mutex<SterileLauncherActivationState>>,
}

enum SterileLauncherActivationState {
    Waiting,
    Accepted {
        request_digest: [u8; 32],
        status: SterileLauncherStatusV1,
    },
}

#[derive(Debug)]
struct ExactSterileClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    required_uri: Arc<str>,
}

impl ClientCertVerifier for ExactSterileClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let (remainder, certificate) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let matches = remainder.is_empty()
            && certificate
                .subject_alternative_name()
                .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?
                .is_some_and(|extension| {
                    extension.value.general_names.iter().any(
                        |name| matches!(name, GeneralName::URI(uri) if *uri == &*self.required_uri),
                    )
                });
        if !matches {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}

const MAX_STERILE_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_STERILE_TLS_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Args)]
struct CompilerCacheCaptureArgs {
    #[arg(long, default_value = compiler_cache_archive::DEFAULT_CACHE_ROOT)]
    cache_root: PathBuf,

    #[arg(long, default_value = compiler_cache_archive::DEFAULT_CAPTURE_ARCHIVE)]
    archive: PathBuf,

    /// Canonical Foam identity JSON. Reads bounded bytes from stdin when omitted.
    #[arg(long)]
    identity_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CompilerCacheRestoreArgs {
    #[arg(long, default_value = compiler_cache_archive::DEFAULT_CACHE_ROOT)]
    cache_root: PathBuf,

    #[arg(long, default_value = compiler_cache_archive::DEFAULT_RESTORE_ARCHIVE)]
    archive: PathBuf,

    #[arg(long)]
    expected_sha256: String,

    /// Canonical Foam identity JSON. Reads bounded bytes from stdin when omitted.
    #[arg(long)]
    identity_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CompilerCacheStageArchiveArgs {
    #[arg(long)]
    expected_sha256: String,
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

#[derive(Debug, Args, Default)]
struct SterileLeaseGateArgs {
    #[arg(long, env = "SANDBOXWICH_STERILE_LEASE_ID")]
    lease_id: Option<Uuid>,

    #[arg(long, env = "SANDBOXWICH_STERILE_LEASE_GENERATION")]
    generation: Option<u64>,

    #[arg(long, env = "SANDBOXWICH_STERILE_LEASE_ATTESTATION_FILE")]
    attestation_file: Option<PathBuf>,

    #[arg(long, env = "SANDBOXWICH_STERILE_ORGANIZATION_ID")]
    organization_id: Option<String>,

    #[arg(long, env = "SANDBOXWICH_STERILE_WORKSPACE_ID")]
    workspace_id: Option<String>,

    #[arg(long, env = "SANDBOXWICH_STERILE_THREAD_ID")]
    thread_id: Option<String>,

    #[arg(long, env = "SANDBOXWICH_STERILE_RUNNER_SESSION_ID")]
    runner_session_id: Option<String>,
}

#[derive(Debug)]
struct SterileLeaseBootstrap {
    lease_id: Uuid,
    generation: u64,
    attestation_file: PathBuf,
    organization_id: String,
    workspace_id: String,
    thread_id: String,
    runner_session_id: String,
}

impl SterileLeaseGateArgs {
    fn into_bootstrap(self) -> anyhow::Result<Option<SterileLeaseBootstrap>> {
        match (
            self.lease_id,
            self.generation,
            self.attestation_file,
            self.organization_id,
            self.workspace_id,
            self.thread_id,
            self.runner_session_id,
        ) {
            (None, None, None, None, None, None, None) => Ok(None),
            (
                Some(lease_id),
                Some(generation),
                Some(attestation_file),
                Some(organization_id),
                Some(workspace_id),
                Some(thread_id),
                Some(runner_session_id),
            ) => Ok(Some(SterileLeaseBootstrap {
                lease_id,
                generation,
                attestation_file,
                organization_id,
                workspace_id,
                thread_id,
                runner_session_id,
            })),
            _ => bail!(
                "sterile-cell startup requires lease id, generation, attestation file, organization, workspace, thread, and runner session together"
            ),
        }
    }
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

    /// Sterile-cell lease fence. When any field in this group is configured,
    /// all fields are required and the daemon validates the short-lived
    /// attestation before reporting readiness or claiming tenant work.
    #[command(flatten)]
    sterile_lease_gate: SterileLeaseGateArgs,

    /// Immutable scheduler-derived identity of a purpose-created sterile pool
    /// pod. The Kubernetes provider renders the exact JSON marker; ordinary
    /// pods have no value and therefore reject gated resident jobs.
    #[arg(long, env = "SANDBOXWICH_STERILE_POOL_CANDIDATE_V1")]
    sterile_pool_candidate: Option<String>,

    #[arg(long, env = "SANDBOXWICH_PROVIDER_POD_NAME")]
    provider_pod_name: Option<String>,

    #[arg(long, env = "SANDBOXWICH_PROVIDER_POD_UID")]
    provider_pod_uid: Option<String>,

    /// Pre-provisioned sandbox-scoped guest credential (`sbw_gtok_...`, see
    /// GH-64's guest-token endpoint) to use for guest-facing calls
    /// (claim/renew/complete/fail/output, guest-health) instead of the
    /// worker-wide `--api-token`. Takes precedence over
    /// `--guest-token-file`/`SANDBOXWICH_GUEST_TOKEN_FILE` below when both
    /// somehow resolve (mirrors `--api-token`'s own file-over-literal
    /// precedence via `resolve_api_token`).
    #[arg(long, env = "SANDBOXWICH_GUEST_TOKEN")]
    guest_token: Option<String>,

    /// Path to a file containing the guest token, mirroring
    /// `--api-token-file`'s mounted read-only Secret delivery; takes
    /// precedence over `--guest-token`/`SANDBOXWICH_GUEST_TOKEN` when set.
    #[arg(long, env = "SANDBOXWICH_GUEST_TOKEN_FILE")]
    guest_token_file: Option<PathBuf>,

    /// TTL requested when this daemon self-mints its own sandbox-scoped
    /// guest token. Only used when neither `--guest-token` nor
    /// `--guest-token-file` resolves to a token and `--worker-id` is set;
    /// ignored otherwise.
    #[arg(
        long,
        env = "SANDBOXWICH_GUEST_TOKEN_TTL_SECONDS",
        default_value_t = DEFAULT_GUEST_TOKEN_TTL_SECS
    )]
    guest_token_ttl_seconds: u64,

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

    /// Maximum number of resident processes this daemon supervises concurrently.
    #[arg(long, env = "SANDBOXWICH_MAX_RESIDENT_PROCESSES", default_value_t = 8)]
    max_resident_processes: usize,
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
        Command::Daemon(args) => daemon(*args).await,
        Command::SterileLauncher(args) => sterile_launcher(args).await,
        Command::AgentSandboxActivate(args) => agent_sandbox_activate(args),
        Command::AgentSandboxLauncher(args) => agent_sandbox_launcher(args),
        Command::AgentSandboxPreclaim(args) => agent_sandbox_preclaim(args),
        Command::Exec(args) => exec(args).await,
        Command::WriteFile(args) => write_file(args).await,
        Command::ReadFile(args) => read_file(args).await,
        Command::CompilerCacheCapture(args) => compiler_cache_capture(args),
        Command::CompilerCacheRestore(args) => compiler_cache_restore(args),
        Command::CompilerCachePrepareWorkspace => {
            compiler_cache_archive::prepare_workspace_boundary()
        }
        Command::CompilerCacheHelper => compiler_cache_archive::run_helper(),
        Command::CompilerCacheStageArchive(args) => {
            let summary = compiler_cache_archive::stage_restore_archive(&args.expected_sha256)?;
            println!("{}", serde_json::to_string(&summary)?);
            Ok(())
        }
    }
}

fn agent_sandbox_activate(args: AgentSandboxActivateArgs) -> anyhow::Result<()> {
    let bundle: sandboxwich_core::AgentSandboxActivationV1 =
        serde_json::from_slice(&std::fs::read(&args.bundle)?)
            .context("decode Agent Sandbox activation bundle")?;
    bundle
        .validate_shape(Utc::now())
        .map_err(|error| anyhow::anyhow!(error))?;
    Uuid::parse_str(&bundle.nonce)
        .map_err(|_| anyhow::anyhow!("agent_sandbox_activation_nonce_invalid"))?;
    let expected = [
        (
            "claim_uid",
            args.expected_claim_uid.as_deref(),
            bundle.claim_uid.as_str(),
        ),
        (
            "sandbox_uid",
            args.expected_sandbox_uid.as_deref(),
            bundle.sandbox_uid.as_str(),
        ),
        (
            "pod_uid",
            args.expected_pod_uid.as_deref(),
            bundle.pod_uid.as_str(),
        ),
        (
            "image_digest",
            args.expected_image_digest.as_deref(),
            bundle.image_digest.as_str(),
        ),
        (
            "bootstrap_digest",
            args.expected_bootstrap_digest.as_deref(),
            bundle.bootstrap_digest.as_str(),
        ),
        (
            "policy_digest",
            args.expected_policy_digest.as_deref(),
            bundle.policy_digest.as_str(),
        ),
    ];
    validate_agent_sandbox_bindings(&bundle, expected)?;
    let public_key = BASE64.decode(std::fs::read_to_string(&args.public_key)?.trim())?;
    let signature = BASE64.decode(bundle.signature.trim())?;
    let payload = bundle.signing_payload()?;
    UnparsedPublicKey::new(&ED25519, public_key.as_slice())
        .verify(&payload, &signature)
        .map_err(|_| anyhow::anyhow!("agent_sandbox_activation_signature_invalid"))?;
    std::fs::create_dir_all(&args.nonce_dir)?;
    let nonce_path = args.nonce_dir.join(&bundle.nonce);
    let created = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&nonce_path);
    match created {
        Ok(file) => drop(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(anyhow::anyhow!("agent_sandbox_activation_replay"));
        }
        Err(error) => return Err(error).context("create Agent Sandbox activation nonce"),
    }
    // The warm pod's long-lived entrypoint is waiting on this bundle. Once
    // the signed one-shot has been consumed, that entrypoint execs the real
    // launcher in the claimed pod; activation itself returns promptly.
    let marker = Path::new("/run/sandboxwich/activation.ready");
    let marker_tmp = marker.with_extension("ready.tmp");
    let mut marker_file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_tmp)
    {
        Ok(file) => file,
        Err(error) => {
            let _ = std::fs::remove_file(&nonce_path);
            return Err(error).context("stage one-shot Agent Sandbox activation marker");
        }
    };
    if let Err(error) = marker_file
        .write_all(bundle.nonce.as_bytes())
        .and_then(|_| marker_file.sync_all())
    {
        let _ = std::fs::remove_file(&marker_tmp);
        let _ = std::fs::remove_file(&nonce_path);
        return Err(error).context("write one-shot Agent Sandbox activation marker");
    }
    drop(marker_file);
    if let Err(error) = std::fs::rename(&marker_tmp, marker) {
        let _ = std::fs::remove_file(&marker_tmp);
        let _ = std::fs::remove_file(&nonce_path);
        return Err(error).context("commit one-shot Agent Sandbox activation marker");
    }
    println!("{}", serde_json::to_string(&bundle)?);
    Ok(())
}

fn validate_agent_sandbox_bindings(
    bundle: &sandboxwich_core::AgentSandboxActivationV1,
    expected: [(&str, Option<&str>, &str); 6],
) -> anyhow::Result<()> {
    for (name, value, actual) in expected {
        let value = value.context(format!("agent_sandbox_expected_{name}_missing"))?;
        if value != actual {
            bail!("agent_sandbox_activation_{name}_mismatch");
        }
    }
    if bundle.nonce.len() > 128
        || bundle.nonce.is_empty()
        || !bundle
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("agent_sandbox_activation_nonce_invalid");
    }
    Ok(())
}

fn agent_sandbox_launcher(args: AgentSandboxLauncherArgs) -> anyhow::Result<()> {
    let bundle: sandboxwich_core::AgentSandboxActivationV1 =
        serde_json::from_slice(&std::fs::read(&args.bundle)?)?;
    bundle
        .validate_shape(Utc::now())
        .map_err(|error| anyhow::anyhow!(error))?;
    let marker_nonce = std::fs::read_to_string(&args.activation_marker)?;
    anyhow::ensure!(
        marker_nonce == bundle.nonce,
        "agent_sandbox_activation_marker_mismatch"
    );
    std::fs::write(&args.ready_file, bundle.pod_uid.as_bytes())?;
    loop {
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn agent_sandbox_preclaim(args: AgentSandboxPreclaimArgs) -> anyhow::Result<()> {
    loop {
        if args.activation_marker.is_file() {
            return agent_sandbox_launcher(AgentSandboxLauncherArgs {
                bundle: args.bundle,
                ready_file: args.ready_file,
                activation_marker: args.activation_marker,
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn compiler_cache_capture(args: CompilerCacheCaptureArgs) -> anyhow::Result<()> {
    let identity = compiler_cache_archive::read_identity(args.identity_file.as_deref())?;
    let summary = compiler_cache_archive::capture(&args.cache_root, &identity, &args.archive)?;
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}

fn compiler_cache_restore(args: CompilerCacheRestoreArgs) -> anyhow::Result<()> {
    let identity = compiler_cache_archive::read_identity(args.identity_file.as_deref())?;
    let summary = compiler_cache_archive::restore_for_workload(
        &args.archive,
        &args.expected_sha256,
        &identity,
        &args.cache_root,
    )?;
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
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
    let sterile_lease_bootstrap = args.sterile_lease_gate.into_bootstrap()?;
    let api_token = resolve_api_token(args.api_token_file, args.api_token)?;
    let client = build_api_client(api_token.as_deref(), args.tenant.as_deref())?;
    let sandbox_id = SandboxId(args.sandbox_id);
    let mut sterile_pool_candidate = args
        .sterile_pool_candidate
        .as_deref()
        .map(serde_json::from_str::<sandboxwich_core::SterilePoolCandidateV1>)
        .transpose()
        .context("SANDBOXWICH_STERILE_POOL_CANDIDATE_V1 is not a valid candidate marker")?;
    if let Some(candidate) = sterile_pool_candidate.as_ref() {
        anyhow::ensure!(
            candidate.cell_id.0 == sandbox_id.0,
            "sterile pool candidate cell does not match SANDBOXWICH_SANDBOX_ID"
        );
    }
    if let Some(candidate) = sterile_pool_candidate.as_mut() {
        let pod_name = args
            .provider_pod_name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context("sterile pool candidate requires SANDBOXWICH_PROVIDER_POD_NAME")?;
        let pod_uid = args
            .provider_pod_uid
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context("sterile pool candidate requires SANDBOXWICH_PROVIDER_POD_UID")?;
        candidate.pod_name = Some(pod_name.to_string());
        candidate.pod_uid = Some(pod_uid.to_string());
    }

    // A daemon with a worker id is an executor. It must not claim work until
    // it has a credential bound to this exact sandbox: falling back to the
    // worker-wide client after one transient mint failure would both strand
    // guest-token recovery and widen the authority of subsequent claims.
    let guest_credential = guest_credential_source(
        resolve_api_token(args.guest_token_file, args.guest_token)?,
        args.worker_id,
        args.guest_token_ttl_seconds,
    );
    let mut claim_budget = HeartbeatFailureBudget::new(args.claim_failure_threshold.max(1));
    let mut claim_backoff = Backoff::new(Duration::from_millis(args.idle_sleep_ms.max(1)));

    let mut guest_session = with_retry(
        &mut claim_budget,
        &mut claim_backoff,
        "resolve_guest_session",
        || {
            resolve_guest_session(
                &client,
                &api,
                args.tenant.as_deref(),
                sandbox_id,
                guest_credential.clone(),
            )
        },
    )
    .await?;
    // Provided tokens lack expires_at; schedule first refresh from now+TTL so
    // the mounted secret cannot silently die at the API's 3600s default.
    if guest_session.expires_at.is_none() && guest_session.can_refresh {
        guest_session.expires_at =
            Some(Utc::now() + chrono::Duration::seconds(guest_session.ttl_seconds as i64));
    }

    let sterile_lease =
        validate_sterile_lease_gate(&guest_session.client, &api, sterile_lease_bootstrap).await?;

    let mut iterations = 0_u64;
    let heartbeat_interval = Duration::from_millis(args.heartbeat_interval_ms.max(1));
    post_guest_health(
        &guest_session.client,
        &api,
        sandbox_id,
        GuestStatus::Ready,
        None,
    )
    .await?;
    let heartbeat_task = tokio::spawn(heartbeat_loop(
        guest_session.client.clone(),
        api.clone(),
        sandbox_id,
        heartbeat_interval,
        args.heartbeat_failure_threshold.max(1),
    ));

    // Tracks consecutive failures across guest authentication, claim_lease,
    // and the guest-health report posted after a failed lease: all require
    // reachability of the control plane and use the same bounded backoff.
    let mut resident_processes = ResidentProcessSupervisor::new(args.max_resident_processes);

    let daemon_loop = async {
        loop {
            while let Some(completion) = resident_processes.try_reap() {
                reconcile_resident_completion(
                    &guest_session.client,
                    &api,
                    sandbox_id,
                    completion,
                    &mut claim_budget,
                    &mut claim_backoff,
                )
                .await?;
            }
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

            match guest_session.ensure_fresh(&api).await {
                Ok(()) => {
                    claim_budget.record_success();
                    claim_backoff.reset();
                }
                Err(error) if error.is_terminal_auth_failure() => {
                    bail!(
                        "sandboxwich-agent: terminal guest auth failure during refresh_guest_token: {error}"
                    );
                }
                Err(error) if error.is_recoverable() => {
                    // Soft-fail refresh: keep the existing credential until the
                    // next loop; claim will still surface a terminal 401 if the
                    // token is already dead.
                    eprintln!(
                        "sandboxwich-agent: refresh_guest_token failed (recoverable): {error}"
                    );
                }
                Err(error) => {
                    bail!("sandboxwich-agent: refresh_guest_token failed: {error}");
                }
            }

            if let Some(worker_id) = args.worker_id {
                let claim_response =
                    with_retry(&mut claim_budget, &mut claim_backoff, "claim_lease", || {
                        claim_lease(
                            &guest_session.client,
                            &api,
                            worker_id,
                            sandbox_id,
                            args.lease_seconds,
                            !resident_processes.is_full(),
                            sterile_pool_candidate.is_some(),
                        )
                    })
                    .await?;

                if let Some(lease) = claim_response.lease {
                    if lease.job.kind == JobKind::RunResidentProcess {
                        let metadata = match ResidentProcessTaskMetadata::from_lease(&lease) {
                            Ok(metadata) => metadata,
                            Err(error) => {
                                fail_resident_lease_and_report(
                                    &guest_session.client,
                                    &api,
                                    sandbox_id,
                                    lease.id,
                                    format!(
                                        "resident job {} has invalid supervision metadata: {error}",
                                        lease.job_id
                                    ),
                                    &mut claim_budget,
                                    &mut claim_backoff,
                                )
                                .await?;
                                continue;
                            }
                        };
                        if resident_processes.is_full() {
                            fail_resident_lease_and_report(
                                &guest_session.client,
                                &api,
                                sandbox_id,
                                lease.id,
                                format!(
                                    "resident-process supervisor capacity exhausted while claiming \
                                     job {} process {} generation {}",
                                    metadata.job_id, metadata.process_id, metadata.generation
                                ),
                                &mut claim_budget,
                                &mut claim_backoff,
                            )
                            .await?;
                            continue;
                        }
                        let client = guest_session.client.clone();
                        let api = api.clone();
                        let sterile_cell_lease = sterile_lease.clone();
                        let sterile_pool_candidate = sterile_pool_candidate.clone();
                        resident_processes.spawn(metadata, async move {
                            handle_lease(
                                &client,
                                &api,
                                sandbox_id,
                                lease,
                                args.max_captured_output_bytes,
                                sterile_cell_lease,
                                sterile_pool_candidate,
                            )
                            .await
                        })?;
                    } else if let Err(error) = handle_lease(
                        &guest_session.client,
                        &api,
                        sandbox_id,
                        lease,
                        args.max_captured_output_bytes,
                        sterile_lease.clone(),
                        sterile_pool_candidate.clone(),
                    )
                    .await
                    {
                        with_retry(
                            &mut claim_budget,
                            &mut claim_backoff,
                            "post_guest_health",
                            || {
                                post_guest_health(
                                    &guest_session.client,
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
    };
    let mut daemon_result =
        run_until_sterile_lease_expiry(daemon_loop, sterile_lease.as_ref()).await;

    for completion in resident_processes.shutdown().await {
        if let Err(shutdown_error) = reconcile_resident_completion(
            &guest_session.client,
            &api,
            sandbox_id,
            completion,
            &mut claim_budget,
            &mut claim_backoff,
        )
        .await
        {
            if daemon_result.is_ok() {
                daemon_result = Err(shutdown_error);
            } else {
                eprintln!(
                    "sandboxwich-agent: resident-process shutdown reconciliation also failed: \
                     {shutdown_error}"
                );
            }
        }
    }

    if heartbeat_task.is_finished() {
        heartbeat_task.await.context("heartbeat task failed")??;
    } else {
        heartbeat_task.abort();
        let _ = heartbeat_task.await;
    }

    daemon_result
}

async fn run_until_sterile_lease_expiry<F>(
    daemon: F,
    sterile_lease: Option<&sandboxwich_core::SterileCellLeaseV1>,
) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    let Some(lease) = sterile_lease else {
        return daemon.await;
    };
    let time_to_expiry = (lease.expires_at - Utc::now())
        .to_std()
        .unwrap_or(Duration::ZERO);
    tokio::pin!(daemon);
    tokio::select! {
        result = &mut daemon => result,
        () = tokio::time::sleep(time_to_expiry) => {
            Err(anyhow::anyhow!("sterile-cell lease expired; stopping tenant execution"))
        }
    }
}

async fn validate_sterile_lease_gate(
    client: &reqwest::Client,
    api: &str,
    bootstrap: Option<SterileLeaseBootstrap>,
) -> anyhow::Result<Option<sandboxwich_core::SterileCellLeaseV1>> {
    let Some(bootstrap) = bootstrap else {
        return Ok(None);
    };
    let file = tokio::fs::File::open(&bootstrap.attestation_file)
        .await
        .with_context(|| {
            format!(
                "read sterile-cell lease attestation from {}",
                bootstrap.attestation_file.display()
            )
        })?;
    let mut lease_attestation = Vec::with_capacity(1025);
    file.take(1025)
        .read_to_end(&mut lease_attestation)
        .await
        .with_context(|| {
            format!(
                "read sterile-cell lease attestation from {}",
                bootstrap.attestation_file.display()
            )
        })?;
    anyhow::ensure!(
        lease_attestation.len() <= 1024,
        "sterile-cell lease attestation file is empty or oversized"
    );
    let lease_attestation = String::from_utf8(lease_attestation)
        .context("sterile-cell lease attestation is not UTF-8")?;
    let lease_attestation = lease_attestation.trim();
    anyhow::ensure!(
        !lease_attestation.is_empty(),
        "sterile-cell lease attestation file is empty or oversized"
    );
    let response = client
        .post(format!(
            "{api}/sterile-cell-leases/{}/validate",
            bootstrap.lease_id
        ))
        .json(&ValidateSterileCellLeaseRequestV1 {
            lease_attestation: lease_attestation.to_string(),
            generation: bootstrap.generation,
            organization_id: bootstrap.organization_id,
            workspace_id: bootstrap.workspace_id,
            thread_id: bootstrap.thread_id,
            runner_session_id: bootstrap.runner_session_id,
        })
        .send()
        .await
        .context("validate sterile-cell lease attestation")?;
    let validated: ValidateSterileCellLeaseResponseV1 = decode_json(response)
        .await
        .map_err(|error| anyhow::anyhow!("sterile-cell lease attestation rejected: {error}"))?;
    Ok(Some(validated.lease))
}

async fn fail_lease_retryable(
    client: &reqwest::Client,
    api: &str,
    lease_id: LeaseId,
    error: String,
) -> Result<LeaseResponse, AgentRequestError> {
    let response = client
        .post(format!("{api}/leases/{lease_id}/fail"))
        .json(&FailLeaseRequest { error, retry: true })
        .send()
        .await?;
    decode_json(response).await
}

async fn fail_resident_lease_and_report(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    lease_id: LeaseId,
    error: String,
    claim_budget: &mut HeartbeatFailureBudget,
    claim_backoff: &mut Backoff,
) -> anyhow::Result<()> {
    // Use an independent retry budget for terminal lease reconciliation. A
    // resident failure must not merely consume the daemon's claim budget and
    // leave its exact lease active until expiry.
    let mut fail_budget = HeartbeatFailureBudget::new(3);
    let mut fail_backoff = Backoff::new(Duration::from_millis(100));
    with_retry(
        &mut fail_budget,
        &mut fail_backoff,
        "fail_resident_lease",
        || fail_lease_retryable(client, api, lease_id, error.clone()),
    )
    .await?;
    with_retry(claim_budget, claim_backoff, "post_guest_health", || {
        post_guest_health(
            client,
            api,
            sandbox_id,
            GuestStatus::Unhealthy,
            Some(error.clone()),
        )
    })
    .await
}

async fn reconcile_resident_completion(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    completion: ResidentProcessTaskCompletion,
    claim_budget: &mut HeartbeatFailureBudget,
    claim_backoff: &mut Backoff,
) -> anyhow::Result<()> {
    let Some((metadata, cause, cancelled_during_shutdown)) = completion.into_failure() else {
        return Ok(());
    };
    let error = format!(
        "resident process {} ({}) generation {} for job {} lease {} failed: {cause}",
        metadata.process_id, metadata.name, metadata.generation, metadata.job_id, metadata.lease_id,
    );
    eprintln!("sandboxwich-agent: {error}");
    if cancelled_during_shutdown
        && let Err(observation_error) = post_resident_observation(
            client,
            api,
            metadata.process_id,
            ResidentProcessObservationRequest {
                generation: metadata.generation,
                lease_id: metadata.lease_id.0,
                observed_state: ResidentProcessObservedState::Lost,
                pid: None,
                exit_code: None,
                error_code: Some("daemon_shutdown".into()),
                error_message: Some("resident process was stopped during daemon shutdown".into()),
                provider_pod_name: None,
                provider_pod_uid: None,
            },
        )
        .await
    {
        eprintln!(
            "sandboxwich-agent: failed to post Lost observation for resident process {} during \
             shutdown: {observation_error}",
            metadata.process_id
        );
    }
    fail_resident_lease_and_report(
        client,
        api,
        sandbox_id,
        metadata.lease_id,
        error,
        claim_budget,
        claim_backoff,
    )
    .await
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
    Configuration(String),
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
            AgentRequestError::Configuration(error) => {
                write!(f, "request configuration failed: {error}")
            }
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
            AgentRequestError::Configuration(_) => None,
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
        if self.is_terminal_auth_failure() {
            return false;
        }
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
            AgentRequestError::Configuration(_) => false,
        }
    }

    /// Guest-token expiry/revocation (and plain 401) will not heal by retrying.
    /// The daemon must exit so the control plane can archive the sandbox rather
    /// than CrashLoop on a permanent auth failure.
    fn is_terminal_auth_failure(&self) -> bool {
        let Self::Status { status, body } = self else {
            return false;
        };
        if *status == reqwest::StatusCode::UNAUTHORIZED {
            return true;
        }
        if *status != reqwest::StatusCode::CONFLICT && *status != reqwest::StatusCode::FORBIDDEN {
            return false;
        }
        serde_json::from_str::<ErrorEnvelope>(body).is_ok_and(|envelope| {
            matches!(
                envelope.code.as_str(),
                "guest_token_expired" | "guest_token_revoked" | "lease_cancelled"
            )
        })
    }

    fn is_resident_desired_stop(&self) -> bool {
        let Self::Status { body, .. } = self else {
            return false;
        };
        serde_json::from_str::<ErrorEnvelope>(body)
            .is_ok_and(|envelope| envelope.code == "resident_process_stopped")
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
            Err(error) if error.is_terminal_auth_failure() => {
                bail!(
                    "sandboxwich-agent: terminal guest auth failure during {operation_name}: {error}"
                );
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
            stdin: None,
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

/// Which sandbox-scoped guest credential (if any) `resolve_guest_client` should
/// use, decided purely from already-resolved inputs (no I/O), so the
/// precedence rule itself is unit-testable without a live server or
/// filesystem.
#[derive(Clone, Debug, Eq, PartialEq)]
enum GuestCredentialSource {
    /// A guest token was supplied directly (via `--guest-token[-file]`); use it
    /// as-is and never call the mint endpoint.
    Provided(String),
    /// No guest token was supplied, but a worker id is configured: self-mint
    /// one bound to `(worker_id, sandbox_id)` via the worker-scoped client.
    SelfMint { worker_id: Uuid, ttl_seconds: u64 },
    /// Neither a guest token nor a worker id is available; there is nothing to
    /// mint or use, so the caller falls back to the worker-wide client.
    None,
}

fn guest_credential_source(
    resolved_guest_token: Option<String>,
    worker_id: Option<Uuid>,
    ttl_seconds: u64,
) -> GuestCredentialSource {
    if let Some(token) = resolved_guest_token {
        GuestCredentialSource::Provided(token)
    } else if let Some(worker_id) = worker_id {
        GuestCredentialSource::SelfMint {
            worker_id,
            ttl_seconds,
        }
    } else {
        GuestCredentialSource::None
    }
}

/// Live guest credential held by the daemon, with TTL-driven refresh so a
/// fixed 3600s mint is not a deterministic death mode for long-lived sandboxes.
struct GuestAuthSession {
    client: reqwest::Client,
    expires_at: Option<DateTime<Utc>>,
    ttl_seconds: u64,
    sandbox_id: SandboxId,
    tenant: Option<String>,
    /// When set, initial mint used the worker credential; refresh uses the
    /// guest-principal refresh endpoint once a guest token exists.
    worker_client: reqwest::Client,
    worker_id: Option<Uuid>,
    can_refresh: bool,
}

impl GuestAuthSession {
    fn needs_refresh(&self, now: DateTime<Utc>) -> bool {
        if !self.can_refresh {
            return false;
        }
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        let lifetime = chrono::Duration::seconds(self.ttl_seconds.max(1) as i64);
        let refresh_after = expires_at
            - chrono::Duration::milliseconds(
                (lifetime.num_milliseconds() as f64 * (1.0 - GUEST_TOKEN_REFRESH_FRACTION)) as i64,
            );
        now >= refresh_after
    }

    async fn ensure_fresh(&mut self, api: &str) -> Result<(), AgentRequestError> {
        if !self.needs_refresh(Utc::now()) {
            return Ok(());
        }
        let minted =
            refresh_guest_token(&self.client, api, self.sandbox_id, self.ttl_seconds).await;
        let minted = match minted {
            Ok(response) => response,
            Err(error) if error.is_terminal_auth_failure() => return Err(error),
            Err(error) => {
                // Fall back to re-mint via worker credential when available
                // (e.g. self-mint daemons before the refresh route is reachable).
                let Some(worker_id) = self.worker_id else {
                    return Err(error);
                };
                mint_guest_token(
                    &self.worker_client,
                    api,
                    worker_id,
                    self.sandbox_id,
                    self.ttl_seconds,
                )
                .await?
            }
        };
        self.client = build_api_client(Some(&minted.token), self.tenant.as_deref())
            .map_err(|error| AgentRequestError::Configuration(error.to_string()))?;
        self.expires_at = Some(minted.expires_at);
        let ttl = (minted.expires_at - Utc::now()).num_seconds().max(1) as u64;
        self.ttl_seconds = ttl.min(86_400);
        Ok(())
    }
}

/// Resolves the credential this daemon uses for every guest-facing call
/// (claim/renew/complete/fail/output, guest-health): a pre-provisioned,
/// sandbox-scoped guest token if one was supplied (`--guest-token`/
/// `--guest-token-file`, following the same file-over-literal precedence as
/// `resolve_api_token`), otherwise one freshly self-minted -- via
/// `worker_client`, the worker-scoped credential also used for
/// `--api-token`/`--api-token-file` -- and bound to exactly this
/// `(worker_id, sandbox_id)`.
///
/// A daemon which has a worker id must obtain a guest credential before it
/// can claim executor work. Recoverable mint failures are deliberately
/// returned to the daemon's bounded retry loop instead of falling back to the
/// worker credential, which would permanently pin the daemon to broader
/// authority after one transient outage.
async fn resolve_guest_session(
    worker_client: &reqwest::Client,
    api: &str,
    tenant: Option<&str>,
    sandbox_id: SandboxId,
    credential: GuestCredentialSource,
) -> Result<GuestAuthSession, AgentRequestError> {
    match credential {
        GuestCredentialSource::Provided(token) => {
            // Mounted/static guest tokens have no known expires_at. Refresh
            // still works once the token is live (guest-principal refresh).
            let client = build_api_client(Some(&token), tenant)
                .map_err(|error| AgentRequestError::Configuration(error.to_string()))?;
            Ok(GuestAuthSession {
                client,
                expires_at: None,
                ttl_seconds: DEFAULT_GUEST_TOKEN_TTL_SECS,
                sandbox_id,
                tenant: tenant.map(str::to_owned),
                worker_client: worker_client.clone(),
                worker_id: None,
                // Provided tokens can refresh once they have an expires_at
                // after the first successful refresh, or we bootstrap refresh
                // by treating them as immediately refreshable at start+TTL.
                can_refresh: true,
            })
        }
        GuestCredentialSource::SelfMint {
            worker_id,
            ttl_seconds,
        } => {
            let minted =
                mint_guest_token(worker_client, api, worker_id, sandbox_id, ttl_seconds).await?;
            let client = build_api_client(Some(&minted.token), tenant)
                .map_err(|error| AgentRequestError::Configuration(error.to_string()))?;
            Ok(GuestAuthSession {
                client,
                expires_at: Some(minted.expires_at),
                ttl_seconds,
                sandbox_id,
                tenant: tenant.map(str::to_owned),
                worker_client: worker_client.clone(),
                worker_id: Some(worker_id),
                can_refresh: true,
            })
        }
        GuestCredentialSource::None => Ok(GuestAuthSession {
            client: worker_client.clone(),
            expires_at: None,
            ttl_seconds: DEFAULT_GUEST_TOKEN_TTL_SECS,
            sandbox_id,
            tenant: tenant.map(str::to_owned),
            worker_client: worker_client.clone(),
            worker_id: None,
            can_refresh: false,
        }),
    }
}

/// Mints a sandbox-scoped guest token (`sbw_gtok_...`) bound to exactly
/// `(worker_id, sandbox_id)`, using `client` (the worker-scoped credential)
/// to authenticate the mint call itself. See `resolve_guest_session`.
async fn mint_guest_token(
    client: &reqwest::Client,
    api: &str,
    worker_id: Uuid,
    sandbox_id: SandboxId,
    ttl_seconds: u64,
) -> Result<GuestTokenResponse, AgentRequestError> {
    let response = client
        .post(format!(
            "{api}/workers/{worker_id}/sandboxes/{sandbox_id}/guest-token"
        ))
        .json(&MintGuestTokenRequest {
            ttl_seconds: Some(ttl_seconds),
        })
        .send()
        .await?;
    decode_json(response).await
}

async fn refresh_guest_token(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    ttl_seconds: u64,
) -> Result<GuestTokenResponse, AgentRequestError> {
    let response = client
        .post(format!("{api}/sandboxes/{sandbox_id}/guest-token/refresh"))
        .json(&RefreshGuestTokenRequest {
            ttl_seconds: Some(ttl_seconds),
        })
        .send()
        .await?;
    decode_json(response).await
}

async fn claim_lease(
    client: &reqwest::Client,
    api: &str,
    worker_id: Uuid,
    sandbox_id: SandboxId,
    lease_seconds: Option<u64>,
    include_resident_processes: bool,
    sterile_pool_candidate: bool,
) -> Result<ClaimLeaseResponse, AgentRequestError> {
    // Scope the claim to this daemon's own sandbox and to the only job kind it
    // knows how to execute. `client` here should be the sandbox-scoped guest
    // credential `resolve_guest_client` prefers (see its doc comment) -- when
    // it is, the API enforces this filter as a real security boundary (see
    // the doc comment on `ClaimLeaseRequest`), and a compromised guest process
    // cannot claim anything outside its own sandbox no matter what it puts in
    // this request. If `resolve_guest_client` fell back to the worker-wide
    // token instead, this filtering is advisory only. `handle_lease` below
    // re-checks the claimed job's sandbox and kind after the fact as further
    // defense in depth (e.g. against a future server-side filtering bug),
    // regardless of which credential was used to claim it.
    let response = client
        .post(format!("{api}/workers/{worker_id}/leases/claim"))
        .json(&ClaimLeaseRequest {
            lease_seconds,
            sandbox_id: Some(sandbox_id),
            kinds: Some(guest_claim_kinds(
                include_resident_processes,
                sterile_pool_candidate,
            )),
            wait_ms: None,
        })
        .send()
        .await?;
    decode_json(response).await
}

fn guest_claim_kinds(
    include_resident_processes: bool,
    sterile_pool_candidate: bool,
) -> Vec<JobKind> {
    if sterile_pool_candidate {
        return include_resident_processes
            .then_some(vec![JobKind::RunResidentProcess])
            .unwrap_or_default();
    }
    let mut kinds = vec![JobKind::RunCommand];
    if include_resident_processes {
        kinds.push(JobKind::RunResidentProcess);
    }
    kinds
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum LeaseCancellationReason {
    None = 0,
    DesiredStop = 1,
    LeaseLost = 2,
}

#[derive(Clone)]
struct LeaseCancellation {
    reason: Arc<AtomicU8>,
}

impl LeaseCancellation {
    fn new() -> Self {
        Self {
            reason: Arc::new(AtomicU8::new(LeaseCancellationReason::None as u8)),
        }
    }

    fn cancel(&self, reason: LeaseCancellationReason) {
        let _ = self.reason.compare_exchange(
            LeaseCancellationReason::None as u8,
            reason as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    fn reason(&self) -> LeaseCancellationReason {
        match self.reason.load(Ordering::SeqCst) {
            1 => LeaseCancellationReason::DesiredStop,
            2 => LeaseCancellationReason::LeaseLost,
            _ => LeaseCancellationReason::None,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.reason() != LeaseCancellationReason::None
    }
}

/// If renewal is lost -- `RENEW_ATTEMPTS` consecutive calls fail -- this
/// stops renewing (retrying a lease that's plausibly already gone forever
/// would just hammer the API) and records why the running child was cancelled.
/// A confirmed resident desired-stop is not a lost lease: it must complete as
/// `Stopped`, whereas every other renewal failure is a retryable loss.
fn spawn_lease_renewal_task(
    client: reqwest::Client,
    api: String,
    lease: &sandboxwich_core::JobLease,
    cancellation: LeaseCancellation,
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
                        if error.is_resident_desired_stop() {
                            cancellation.cancel(LeaseCancellationReason::DesiredStop);
                            // The API renewed the lease before returning this
                            // typed stop signal. Keep the renewal task alive
                            // until terminal observation and completion finish.
                            renewed = true;
                            break;
                        }
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
                if cancellation.reason() == LeaseCancellationReason::DesiredStop {
                    eprintln!(
                        "warning: renewing desired-stop lease {lease_id} failed after \
                         {RENEW_ATTEMPTS} attempts ({error}); retaining terminal ownership"
                    );
                    continue;
                }
                eprintln!(
                    "warning: renewing lease {lease_id} failed after {RENEW_ATTEMPTS} attempts \
                     ({error}); cancelling the running command instead of letting it keep \
                     executing against a lease we can no longer prove is still ours"
                );
                cancellation.cancel(LeaseCancellationReason::LeaseLost);
                return;
            }
        }
    })
}

/// Aborts renewal immediately if its owning lease future is itself cancelled.
/// Dropping a bare Tokio `JoinHandle` detaches the task, which would let it
/// keep renewing a lease after its resident child had been killed.
struct LeaseRenewalTask {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl LeaseRenewalTask {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    async fn abort_and_wait(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for LeaseRenewalTask {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

/// Why a claimed lease must be handed back rather than executed. Both variants
/// mean the job merely landed on the wrong executor -- not that it's invalid --
/// so `handle_lease` always fails these with `retry: true`, never `retry: false`,
/// so the intended executor still gets a chance to run it.
#[derive(Debug, Eq, PartialEq)]
enum LeaseScopeViolation {
    /// This daemon executes only guest command and resident-process jobs.
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
                "sandboxwich-agent daemon cannot handle lease kind {kind:?}"
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
    if !matches!(job.kind, JobKind::RunCommand | JobKind::RunResidentProcess) {
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
    sterile_cell_lease: Option<sandboxwich_core::SterileCellLeaseV1>,
    sterile_pool_candidate: Option<sandboxwich_core::SterilePoolCandidateV1>,
) -> anyhow::Result<LeaseResponse> {
    if let Some(violation) = lease_scope_violation(&lease.job, sandbox_id) {
        eprintln!(
            "sandboxwich-agent: claimed lease {} for job {} out of scope for sandbox {sandbox_id} \
             ({violation}); failing with retry so the intended executor can claim it instead",
            lease.id, lease.job.id
        );
        return fail_lease_retryable(client, api, lease.id, violation.to_string())
            .await
            .map_err(Into::into);
    }

    if lease.job.kind == JobKind::RunResidentProcess {
        return handle_resident_process(
            client,
            api,
            sandbox_id,
            lease,
            sterile_cell_lease,
            sterile_pool_candidate,
        )
        .await;
    }

    let request = agent_request_from_payload(&lease.job.payload)?;
    let cancellation = LeaseCancellation::new();
    let renew_task = LeaseRenewalTask::new(spawn_lease_renewal_task(
        client.clone(),
        api.to_string(),
        &lease,
        cancellation.clone(),
    ));

    let result = execute_streaming(
        request,
        Some(client),
        Some(api),
        Some(lease.id),
        max_captured_output_bytes,
        Some(cancellation),
    )
    .await;

    renew_task.abort_and_wait().await;

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

async fn post_resident_observation(
    client: &reqwest::Client,
    api: &str,
    process_id: ResidentProcessId,
    request: ResidentProcessObservationRequest,
) -> anyhow::Result<()> {
    client
        .post(format!(
            "{api}/resident-processes/{process_id}/observations"
        ))
        .json(&request)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// v1 sidecar placement primitive (evalops/sandboxwich#176): if `run_as_uid`
/// is `Some` (only `orb-sidecar` gets one -- see
/// [`sandboxwich_core::resident_process_run_as_uid`]), configure `command`
/// to `setuid`/`setgid` to it before exec, giving the sidecar a uid distinct
/// from this agent's own uid (which is what `orb-executor` and every other
/// resident process inherit by leaving `run_as_uid` at `None`).
///
/// This is a uid-separation boundary WITHIN the same sandbox/container, not
/// a separate trust domain -- a sufficiently privileged process elsewhere in
/// the same sandbox (e.g. a root agent workload) can still read the
/// sidecar's files, ptrace it, or otherwise defeat the separation; see
/// docs/capabilities.md for the full disclosure. If the agent process itself
/// lacks the privilege to change uid (true for the default, non-apex
/// sandbox pod today, which is not granted `SETUID`/`SETGID`), the spawn
/// fails outright with a permission error rather than silently running the
/// sidecar under the workload's own uid -- callers must treat that as the
/// sidecar being unavailable, not as a degraded-but-working sidecar.
fn apply_resident_process_run_as_uid(command: &mut TokioProcessCommand, run_as_uid: Option<u32>) {
    #[cfg(unix)]
    if let Some(uid) = run_as_uid {
        command.uid(uid);
        command.gid(uid);
    }
    #[cfg(not(unix))]
    let _ = (command, run_as_uid);
}

#[cfg(unix)]
fn transfer_resident_bootstrap_ownership(
    file: &std::fs::File,
    run_as_uid: Option<u32>,
) -> std::io::Result<()> {
    if let Some(uid) = run_as_uid {
        std::os::unix::fs::fchown(file, Some(uid), Some(uid))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn transfer_resident_bootstrap_ownership(
    _file: &std::fs::File,
    _run_as_uid: Option<u32>,
) -> std::io::Result<()> {
    Ok(())
}

async fn wait_for_lease_cancellation(cancellation: &LeaseCancellation) {
    while !cancellation.is_cancelled() {
        tokio::time::sleep(CANCEL_POLL_INTERVAL).await;
    }
}

/// A bootstrap delivery is fenced to the active lease and can only be replayed
/// after a terminal observation consumes it. Once an observation can
/// acknowledge that delivery, every subsequent observation must stay on this
/// same lease and retry until it succeeds or renewal confirms cancellation.
async fn post_resident_observation_until_resolved(
    client: &reqwest::Client,
    api: &str,
    process_id: ResidentProcessId,
    request: ResidentProcessObservationRequest,
    cancellation: &LeaseCancellation,
) -> Result<(), LeaseCancellationReason> {
    let mut backoff = Backoff::new(RESIDENT_OBSERVATION_RETRY_DELAY);
    loop {
        if cancellation.is_cancelled() {
            return Err(cancellation.reason());
        }
        match post_resident_observation(client, api, process_id, request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                eprintln!(
                    "warning: posting {:?} for resident process {process_id} lease {} failed; \
                     retrying under the same lease: {error}",
                    request.observed_state, request.lease_id,
                );
                tokio::select! {
                    () = backoff.wait() => {}
                    () = wait_for_lease_cancellation(cancellation) => {
                        return Err(cancellation.reason());
                    }
                }
            }
        }
    }
}

async fn fail_lease_terminal(
    client: &reqwest::Client,
    api: &str,
    lease_id: LeaseId,
    error: String,
) -> Result<LeaseResponse, AgentRequestError> {
    let response = client
        .post(format!("{api}/leases/{lease_id}/fail"))
        .json(&FailLeaseRequest {
            error,
            retry: false,
        })
        .send()
        .await?;
    decode_json(response).await
}

async fn complete_resident_lease(
    client: &reqwest::Client,
    api: &str,
    lease_id: LeaseId,
    process_id: ResidentProcessId,
    generation: u64,
    exit_code: Option<i32>,
) -> anyhow::Result<LeaseResponse> {
    let response = client
        .post(format!("{api}/leases/{lease_id}/complete"))
        .json(&CompleteLeaseRequest {
            result: Some(WorkerJobResult::RunResidentProcess {
                process_id,
                generation,
                exit_code,
            }),
        })
        .send()
        .await?;
    decode_json(response).await.map_err(Into::into)
}

async fn complete_resident_lease_until_resolved(
    client: &reqwest::Client,
    api: &str,
    fence: ResidentLeaseFence,
    exit_code: Option<i32>,
    cancellation: &LeaseCancellation,
) -> Result<LeaseResponse, LeaseCancellationReason> {
    let mut backoff = Backoff::new(RESIDENT_OBSERVATION_RETRY_DELAY);
    loop {
        if cancellation.is_cancelled() {
            return Err(cancellation.reason());
        }
        match complete_resident_lease(
            client,
            api,
            fence.lease_id,
            fence.process_id,
            fence.generation,
            exit_code,
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(error) => {
                eprintln!(
                    "warning: completing resident process {} lease {} failed; retrying under \
                     the same lease: {error}",
                    fence.process_id, fence.lease_id
                );
                tokio::select! {
                    () = backoff.wait() => {}
                    () = wait_for_lease_cancellation(cancellation) => {
                        return Err(cancellation.reason());
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ResidentLeaseFence {
    lease_id: LeaseId,
    process_id: ResidentProcessId,
    generation: u64,
}

async fn complete_desired_stop_resident_lease(
    client: &reqwest::Client,
    api: &str,
    fence: ResidentLeaseFence,
) -> anyhow::Result<LeaseResponse> {
    let request = ResidentProcessObservationRequest {
        generation: fence.generation,
        lease_id: fence.lease_id.0,
        observed_state: ResidentProcessObservedState::Stopped,
        pid: None,
        // Completing with zero is intentional: the API derives the terminal
        // resident state from this typed result too.
        exit_code: Some(0),
        error_code: None,
        error_message: None,
        provider_pod_name: None,
        provider_pod_uid: None,
    };
    let mut backoff = Backoff::new(RESIDENT_OBSERVATION_RETRY_DELAY);
    loop {
        match post_resident_observation(client, api, fence.process_id, request.clone()).await {
            Ok(()) => break,
            Err(error) => eprintln!(
                "warning: reporting desired stop for resident process {} lease {} failed; \
                 retaining terminal ownership and retrying: {error}",
                fence.process_id, fence.lease_id
            ),
        }
        backoff.wait().await;
    }
    backoff.reset();
    loop {
        match complete_resident_lease(
            client,
            api,
            fence.lease_id,
            fence.process_id,
            fence.generation,
            Some(0),
        )
        .await
        {
            Ok(response) => return Ok(response),
            Err(error) => eprintln!(
                "warning: completing desired stop for resident process {} lease {} failed; \
                 retaining terminal ownership and retrying: {error}",
                fence.process_id, fence.lease_id
            ),
        }
        backoff.wait().await;
    }
}

async fn reconcile_resident_cancellation_without_child(
    client: &reqwest::Client,
    api: &str,
    fence: ResidentLeaseFence,
    reason: LeaseCancellationReason,
) -> anyhow::Result<LeaseResponse> {
    if reason == LeaseCancellationReason::DesiredStop {
        return complete_desired_stop_resident_lease(client, api, fence).await;
    }
    fail_lease_terminal(
        client,
        api,
        fence.lease_id,
        format!(
            "resident process lease was cancelled as {reason:?}; bootstrap delivery cannot be retried"
        ),
    )
    .await
    .map_err(Into::into)
}

async fn reconcile_resident_cancellation(
    client: &reqwest::Client,
    api: &str,
    fence: ResidentLeaseFence,
    pid: Option<u32>,
    child: &mut tokio::process::Child,
    reason: LeaseCancellationReason,
) -> anyhow::Result<LeaseResponse> {
    let _ = child.start_kill();
    let _ = child.wait().await;
    if reason == LeaseCancellationReason::DesiredStop {
        return complete_desired_stop_resident_lease(client, api, fence).await;
    }

    post_resident_observation(
        client,
        api,
        fence.process_id,
        ResidentProcessObservationRequest {
            generation: fence.generation,
            lease_id: fence.lease_id.0,
            observed_state: ResidentProcessObservedState::Lost,
            pid,
            exit_code: None,
            error_code: Some("lease_lost".into()),
            error_message: Some("resident process lease renewal was lost".into()),
            provider_pod_name: None,
            provider_pod_uid: None,
        },
    )
    .await?;
    fail_lease_retryable(
        client,
        api,
        fence.lease_id,
        "resident process lease renewal was lost".into(),
    )
    .await
    .map_err(Into::into)
}

async fn handle_resident_process(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    lease: sandboxwich_core::JobLease,
    sterile_cell_lease: Option<sandboxwich_core::SterileCellLeaseV1>,
    sterile_pool_candidate: Option<sandboxwich_core::SterilePoolCandidateV1>,
) -> anyhow::Result<LeaseResponse> {
    handle_resident_process_with_bootstrap_root(
        client,
        api,
        sandbox_id,
        lease,
        sterile_cell_lease,
        sterile_pool_candidate,
        Path::new("/run/sandboxwich/bootstrap"),
    )
    .await
}

async fn validate_resident_sterile_activation(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    fence: Option<&sandboxwich_core::SterileResidentActivationFenceV1>,
    daemon_lease: Option<&sandboxwich_core::SterileCellLeaseV1>,
    pool_candidate: Option<&sandboxwich_core::SterilePoolCandidateV1>,
    activation: Option<&sandboxwich_core::SterileResidentActivationV1>,
) -> anyhow::Result<Option<sandboxwich_core::SterileCellLeaseV1>> {
    match (fence, activation) {
        (None, None) if daemon_lease.is_none() && pool_candidate.is_none() => return Ok(None),
        (Some(fence), Some(activation)) => {
            anyhow::ensure!(
                daemon_lease.is_some() || pool_candidate.is_some(),
                "ordinary agent rejected a gated sterile resident job"
            );
            anyhow::ensure!(
                fence.cell_id.0 == sandbox_id.0
                    && activation.lease_id == fence.lease_id
                    && activation.generation == fence.generation,
                "resident sterile activation does not match the job fence"
            );
        }
        _ => anyhow::bail!("resident sterile activation gated/ungated mismatch"),
    }
    let fence = fence.expect("matched above");
    let activation = activation.expect("matched above");
    let response = client
        .post(format!(
            "{api}/sterile-cell-leases/{}/validate",
            fence.lease_id
        ))
        .json(&ValidateSterileCellLeaseRequestV1 {
            lease_attestation: activation.lease_attestation.clone(),
            generation: activation.generation,
            organization_id: activation.organization_id.clone(),
            workspace_id: activation.workspace_id.clone(),
            thread_id: activation.thread_id.clone(),
            runner_session_id: activation.runner_session_id.clone(),
        })
        .send()
        .await
        .context("revalidate sterile resident activation")?;
    let validated: ValidateSterileCellLeaseResponseV1 = decode_json(response)
        .await
        .map_err(|error| anyhow::anyhow!("sterile resident activation rejected: {error}"))?;
    anyhow::ensure!(
        validated.lease.cell_id == fence.cell_id
            && validated.lease.lease_id == fence.lease_id
            && validated.lease.generation == fence.generation
            && validated.lease.organization_id == activation.organization_id
            && validated.lease.workspace_id == activation.workspace_id
            && validated.lease.thread_id == activation.thread_id
            && validated.lease.runner_session_id == activation.runner_session_id
            && validated.lease.expires_at > Utc::now(),
        "sterile resident activation validation returned a mismatched or expired lease"
    );
    if let Some(daemon_lease) = daemon_lease {
        anyhow::ensure!(
            &validated.lease == daemon_lease,
            "resident sterile activation does not match the legacy startup lease"
        );
    }
    if let Some(candidate) = pool_candidate {
        anyhow::ensure!(
            candidate.cell_id == validated.lease.cell_id
                && candidate.release == validated.lease.release,
            "sterile resident activation does not match the immutable pool candidate"
        );
    }
    Ok(Some(validated.lease))
}

fn prepare_resident_bootstrap_file(
    bootstrap: &ResidentProcessBootstrapReadResponse,
    bootstrap_root: &Path,
    run_as_uid: Option<u32>,
) -> anyhow::Result<()> {
    if bootstrap.target_file.is_empty() {
        anyhow::ensure!(
            bootstrap.content.is_empty() && bootstrap.mode == 0,
            "activation-only resident handoff contains bootstrap file data"
        );
        return Ok(());
    }
    let target = Path::new(&bootstrap.target_file);
    anyhow::ensure!(
        target.starts_with(bootstrap_root),
        "resident bootstrap path is outside the allowed root"
    );
    let parent = target
        .parent()
        .context("resident bootstrap has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(bootstrap.mode);
    let mut file = options
        .open(target)
        .with_context(|| format!("failed to create {}", target.display()))?;
    file.write_all(&bootstrap.content)?;
    file.sync_all()?;
    transfer_resident_bootstrap_ownership(&file, run_as_uid).with_context(|| {
        format!(
            "failed to transfer {} to the resident-process identity",
            target.display()
        )
    })?;
    Ok(())
}

async fn sterile_launcher(args: SterileLauncherArgs) -> anyhow::Result<()> {
    let tls = sterile_launcher_tls_config(
        &args.server_cert_file,
        &args.server_key_file,
        &args.client_ca_file,
        &args.client_uri,
    )?;
    let state = SterileLauncherServerState {
        activation: Arc::new(Mutex::new(SterileLauncherActivationState::Waiting)),
    };
    let app = Router::new()
        .route("/v1/activation", put(accept_sterile_activation))
        .route("/v1/status", get(get_sterile_launcher_status))
        .layer(DefaultBodyLimit::max(MAX_STERILE_BUNDLE_BYTES))
        .with_state(state);
    axum_server::bind_rustls(args.activation_bind, tls)
        .serve(app.into_make_service())
        .await
        .context("serve sterile launcher activation channel")
}

fn validate_sterile_activation_request(bundle: &SterileActivationRequestV1) -> anyhow::Result<()> {
    anyhow::ensure!(
        bundle.version == 1,
        "unsupported sterile activation request version"
    );
    anyhow::ensure!(
        bundle.validated_expires_at > Utc::now(),
        "sterile activation expired before launcher consumption"
    );
    anyhow::ensure!(
        bundle.fence.cell_id == bundle.candidate.cell_id,
        "sterile launcher cell fence mismatch"
    );
    anyhow::ensure!(
        bundle.bootstrap.sterile_activation.is_none(),
        "raw sterile attestation reached the workload handoff"
    );
    let marker: sandboxwich_core::SterilePoolCandidateV1 = serde_json::from_str(
        &std::env::var("SANDBOXWICH_STERILE_POOL_CANDIDATE_V1")
            .context("launcher is missing immutable candidate marker")?,
    )?;
    anyhow::ensure!(
        marker.cell_id == bundle.candidate.cell_id
            && marker.release == bundle.candidate.release
            && marker.agent_image == bundle.candidate.agent_image
            && marker.maestro_image == bundle.candidate.maestro_image
            && marker.service_name == bundle.candidate.service_name,
        "sterile launcher candidate marker mismatch"
    );
    anyhow::ensure!(
        std::env::var("SANDBOXWICH_PROVIDER_POD_NAME")
            .ok()
            .as_deref()
            == bundle.candidate.pod_name.as_deref()
            && std::env::var("SANDBOXWICH_PROVIDER_POD_UID")
                .ok()
                .as_deref()
                == bundle.candidate.pod_uid.as_deref(),
        "sterile launcher Pod identity mismatch"
    );
    continue_candidate_bootstrap_validation(&bundle.bootstrap)
}

async fn accept_sterile_activation(
    State(state): State<SterileLauncherServerState>,
    Json(bundle): Json<SterileActivationRequestV1>,
) -> Result<(StatusCode, Json<SterileLauncherStatusV1>), (StatusCode, &'static str)> {
    validate_sterile_activation_request(&bundle)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "invalid activation"))?;
    let encoded = serde_json::to_vec(&bundle)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "invalid activation"))?;
    if encoded.len() > MAX_STERILE_BUNDLE_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "activation too large"));
    }
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    let accepted = SterileLauncherStatusV1 {
        phase: SterileLauncherPhaseV1::Accepted,
        pid: None,
        exit_code: None,
        error: None,
    };
    let (is_new, status) = register_sterile_activation(&state, digest, accepted).await?;
    if !is_new {
        return Ok((StatusCode::OK, Json(status)));
    }
    tokio::spawn(run_sterile_activation(state, bundle));
    Ok((StatusCode::ACCEPTED, Json(status)))
}

async fn register_sterile_activation(
    state: &SterileLauncherServerState,
    request_digest: [u8; 32],
    accepted: SterileLauncherStatusV1,
) -> Result<(bool, SterileLauncherStatusV1), (StatusCode, &'static str)> {
    let mut activation = state.activation.lock().await;
    match &*activation {
        SterileLauncherActivationState::Waiting => {
            *activation = SterileLauncherActivationState::Accepted {
                request_digest,
                status: accepted.clone(),
            };
            Ok((true, accepted))
        }
        SterileLauncherActivationState::Accepted {
            request_digest: existing,
            status,
        } if existing == &request_digest => Ok((false, status.clone())),
        SterileLauncherActivationState::Accepted { .. } => {
            Err((StatusCode::CONFLICT, "conflicting activation"))
        }
    }
}

async fn run_sterile_activation(
    state: SterileLauncherServerState,
    bundle: SterileActivationRequestV1,
) {
    let terminal = match spawn_and_wait_sterile_maestro(&state, bundle).await {
        Ok(exit_code) => SterileLauncherStatusV1 {
            phase: SterileLauncherPhaseV1::Terminal,
            pid: None,
            exit_code,
            error: None,
        },
        Err(_) => SterileLauncherStatusV1 {
            phase: SterileLauncherPhaseV1::Terminal,
            pid: None,
            exit_code: None,
            error: Some("sterile launcher failed".into()),
        },
    };
    set_sterile_launcher_status(&state, terminal).await;
}

async fn spawn_and_wait_sterile_maestro(
    state: &SterileLauncherServerState,
    bundle: SterileActivationRequestV1,
) -> anyhow::Result<Option<i32>> {
    prepare_resident_bootstrap_file(
        &bundle.bootstrap,
        Path::new("/run/sandboxwich/bootstrap"),
        None,
    )?;
    let (program, argv) = bundle
        .argv
        .split_first()
        .context("sterile launcher argv is empty")?;
    let mut command = TokioProcessCommand::new(program);
    command
        .args(argv)
        .envs(bundle.env)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if let Some(cwd) = bundle.cwd {
        command.current_dir(cwd);
    }
    let mut child = command
        .spawn()
        .context("spawn Maestro from sterile launcher")?;
    set_sterile_launcher_status(
        state,
        SterileLauncherStatusV1 {
            phase: SterileLauncherPhaseV1::Running,
            pid: child.id(),
            exit_code: None,
            error: None,
        },
    )
    .await;
    let status = child
        .wait()
        .await
        .context("wait for sterile Maestro process")?;
    Ok(status.code())
}

async fn set_sterile_launcher_status(
    state: &SterileLauncherServerState,
    status: SterileLauncherStatusV1,
) {
    let mut activation = state.activation.lock().await;
    if let SterileLauncherActivationState::Accepted {
        status: current, ..
    } = &mut *activation
    {
        *current = status;
    }
}

async fn get_sterile_launcher_status(
    State(state): State<SterileLauncherServerState>,
) -> Result<Json<SterileLauncherStatusV1>, StatusCode> {
    let activation = state.activation.lock().await;
    match &*activation {
        SterileLauncherActivationState::Waiting => Err(StatusCode::NOT_FOUND),
        SterileLauncherActivationState::Accepted { status, .. } => Ok(Json(status.clone())),
    }
}

fn continue_candidate_bootstrap_validation(
    bootstrap: &ResidentProcessBootstrapReadResponse,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        bootstrap.content.len() <= MAX_STERILE_BUNDLE_BYTES,
        "candidate bootstrap exceeds the launcher handoff bound"
    );
    if bootstrap.target_file.is_empty() {
        anyhow::ensure!(
            bootstrap.content.is_empty() && bootstrap.mode == 0,
            "activation-only bootstrap is malformed"
        );
    } else {
        anyhow::ensure!(
            Path::new(&bootstrap.target_file).starts_with("/run/sandboxwich/bootstrap"),
            "candidate bootstrap target is outside the launcher bootstrap root"
        );
    }
    Ok(())
}

async fn wait_launcher_status(
    client: &reqwest::Client,
    activation_url: &str,
    phase: SterileLauncherPhaseV1,
    expires_at: DateTime<Utc>,
) -> anyhow::Result<SterileLauncherStatusV1> {
    loop {
        anyhow::ensure!(
            expires_at > Utc::now(),
            "sterile activation expired while waiting for launcher"
        );
        if let Ok(response) = client
            .get(format!("{activation_url}/v1/status"))
            .send()
            .await
            && response.status().is_success()
        {
            let status: SterileLauncherStatusV1 = response.json().await?;
            if status.phase == phase
                || (phase == SterileLauncherPhaseV1::Running
                    && status.phase == SterileLauncherPhaseV1::Terminal)
            {
                return Ok(status);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn read_bounded_sterile_tls_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("inspect sterile activation TLS file {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= MAX_STERILE_TLS_FILE_BYTES,
        "sterile activation TLS file must be a bounded regular file"
    );
    let bytes = std::fs::read(path)
        .with_context(|| format!("read sterile activation TLS file {}", path.display()))?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_STERILE_TLS_FILE_BYTES,
        "sterile activation TLS file must be bounded"
    );
    Ok(bytes)
}

fn sterile_launcher_tls_config(
    cert_file: &Path,
    key_file: &Path,
    client_ca_file: &Path,
    client_uri: &str,
) -> anyhow::Result<RustlsConfig> {
    anyhow::ensure!(
        client_uri.starts_with("spiffe://sandboxwich.dev/sterile-cell/")
            && !client_uri.contains(char::is_whitespace),
        "launcher client URI is invalid"
    );
    let certificates =
        rustls_pemfile::certs(&mut Cursor::new(read_bounded_sterile_tls_file(cert_file)?))
            .collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(!certificates.is_empty(), "launcher certificate is empty");
    let mut key = None;
    for item in rustls_pemfile::read_all(&mut Cursor::new(read_bounded_sterile_tls_file(key_file)?))
    {
        let parsed = match item? {
            Item::Pkcs1Key(value) => rustls::pki_types::PrivateKeyDer::Pkcs1(value),
            Item::Pkcs8Key(value) => rustls::pki_types::PrivateKeyDer::Pkcs8(value),
            Item::Sec1Key(value) => rustls::pki_types::PrivateKeyDer::Sec1(value),
            _ => bail!("launcher key file contains non-key PEM"),
        };
        anyhow::ensure!(
            key.replace(parsed).is_none(),
            "launcher key file contains multiple keys"
        );
    }
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut Cursor::new(read_bounded_sterile_tls_file(
        client_ca_file,
    )?)) {
        roots.add(certificate?)?;
    }
    anyhow::ensure!(!roots.is_empty(), "launcher client CA is empty");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let verifier = Arc::new(ExactSterileClientCertVerifier {
        inner: verifier,
        required_uri: Arc::from(client_uri),
    });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, key.context("launcher key is empty")?)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

fn sterile_activation_http_client() -> anyhow::Result<(reqwest::Client, String)> {
    let activation_url = std::env::var("SANDBOXWICH_STERILE_ACTIVATION_URL")
        .context("candidate control is missing SANDBOXWICH_STERILE_ACTIVATION_URL")?;
    anyhow::ensure!(
        activation_url.starts_with("https://") && !activation_url.ends_with('/'),
        "sterile activation URL must be an HTTPS origin without a trailing slash"
    );
    let cert = PathBuf::from(
        std::env::var("SANDBOXWICH_STERILE_ACTIVATION_CLIENT_CERT_FILE")
            .context("candidate control is missing sterile activation client certificate")?,
    );
    let key = PathBuf::from(
        std::env::var("SANDBOXWICH_STERILE_ACTIVATION_CLIENT_KEY_FILE")
            .context("candidate control is missing sterile activation client key")?,
    );
    let ca = PathBuf::from(
        std::env::var("SANDBOXWICH_STERILE_ACTIVATION_SERVER_CA_FILE")
            .context("candidate control is missing sterile activation server CA")?,
    );
    let mut identity = read_bounded_sterile_tls_file(&cert)?;
    identity.extend_from_slice(&read_bounded_sterile_tls_file(&key)?);
    anyhow::ensure!(
        identity.len() as u64 <= 2 * MAX_STERILE_TLS_FILE_BYTES,
        "sterile activation client identity exceeds bound"
    );
    let client = reqwest::Client::builder()
        .https_only(true)
        .identity(reqwest::Identity::from_pem(&identity)?)
        .add_root_certificate(reqwest::Certificate::from_pem(
            &read_bounded_sterile_tls_file(&ca)?,
        )?)
        .build()?;
    Ok((client, activation_url))
}

#[allow(clippy::too_many_arguments)]
async fn activate_sterile_launcher_after_revalidation(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    fence: &sandboxwich_core::SterileResidentActivationFenceV1,
    daemon_lease: Option<&sandboxwich_core::SterileCellLeaseV1>,
    candidate: &sandboxwich_core::SterilePoolCandidateV1,
    activation: &sandboxwich_core::SterileResidentActivationV1,
    activation_client: &reqwest::Client,
    activation_url: &str,
    argv: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    bootstrap: ResidentProcessBootstrapReadResponse,
) -> anyhow::Result<DateTime<Utc>> {
    let live = validate_resident_sterile_activation(
        client,
        api,
        sandbox_id,
        Some(fence),
        daemon_lease,
        Some(candidate),
        Some(activation),
    )
    .await?
    .context("candidate activation expired before launcher activation")?;
    anyhow::ensure!(
        bootstrap.sterile_activation.is_none(),
        "raw sterile attestation cannot cross the launcher activation channel"
    );
    let request = SterileActivationRequestV1 {
        version: 1,
        candidate: candidate.clone(),
        fence: *fence,
        validated_expires_at: live.expires_at,
        argv,
        cwd,
        env,
        bootstrap,
    };
    let endpoint = format!("{activation_url}/v1/activation");
    loop {
        anyhow::ensure!(
            live.expires_at > Utc::now(),
            "sterile activation expired before launcher acknowledged activation"
        );
        match activation_client.put(&endpoint).json(&request).send().await {
            Ok(response) if response.status().is_success() => break,
            Ok(response) if response.status() == reqwest::StatusCode::CONFLICT => {
                bail!("sterile launcher rejected conflicting activation")
            }
            Ok(response) if response.status().is_client_error() => {
                bail!(
                    "sterile launcher rejected activation: {}",
                    response.status()
                )
            }
            Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    Ok(live.expires_at)
}

#[allow(clippy::too_many_arguments)]
async fn supervise_sterile_launcher(
    client: &reqwest::Client,
    api: &str,
    lease: sandboxwich_core::JobLease,
    process_id: ResidentProcessId,
    generation: u64,
    candidate: sandboxwich_core::SterilePoolCandidateV1,
    activation_client: reqwest::Client,
    activation_url: String,
    expires_at: DateTime<Utc>,
) -> anyhow::Result<LeaseResponse> {
    let cancellation = LeaseCancellation::new();
    let renewal = LeaseRenewalTask::new(spawn_lease_renewal_task(
        client.clone(),
        api.to_string(),
        &lease,
        cancellation.clone(),
    ));
    let outcome = async {
        let started = wait_launcher_status(
            &activation_client,
            &activation_url,
            SterileLauncherPhaseV1::Running,
            expires_at,
        )
        .await?;
        let observation = |observed_state, pid, exit_code, error_code, error_message| {
            ResidentProcessObservationRequest {
                generation,
                lease_id: lease.id.0,
                observed_state,
                pid,
                exit_code,
                error_code,
                error_message,
                provider_pod_name: candidate.pod_name.clone(),
                provider_pod_uid: candidate.pod_uid.clone(),
            }
        };
        post_resident_observation(
            client,
            api,
            process_id,
            observation(
                ResidentProcessObservedState::Starting,
                started.pid,
                None,
                None,
                None,
            ),
        )
        .await?;
        post_resident_observation(
            client,
            api,
            process_id,
            observation(
                ResidentProcessObservedState::Running,
                started.pid,
                None,
                None,
                None,
            ),
        )
        .await?;
        let terminal = wait_launcher_status(
            &activation_client,
            &activation_url,
            SterileLauncherPhaseV1::Terminal,
            expires_at,
        )
        .await?;
        let success = terminal.exit_code == Some(0) && terminal.error.is_none();
        post_resident_observation(
            client,
            api,
            process_id,
            observation(
                if success {
                    ResidentProcessObservedState::Stopped
                } else {
                    ResidentProcessObservedState::Failed
                },
                None,
                terminal.exit_code,
                (!success).then(|| "sterile_launcher_terminal".into()),
                terminal.error,
            ),
        )
        .await?;
        if success {
            complete_resident_lease_until_resolved(
                client,
                api,
                ResidentLeaseFence {
                    lease_id: lease.id,
                    process_id,
                    generation,
                },
                terminal.exit_code,
                &cancellation,
            )
            .await
            .map_err(|reason| {
                anyhow::anyhow!("sterile launcher lease completion cancelled: {reason:?}")
            })
        } else {
            fail_lease_terminal(client, api, lease.id, "sterile launcher failed".into())
                .await
                .map_err(anyhow::Error::from)
        }
    }
    .await;
    renewal.abort_and_wait().await;
    outcome
}

async fn handle_resident_process_with_bootstrap_root(
    client: &reqwest::Client,
    api: &str,
    sandbox_id: SandboxId,
    lease: sandboxwich_core::JobLease,
    sterile_cell_lease: Option<sandboxwich_core::SterileCellLeaseV1>,
    sterile_pool_candidate: Option<sandboxwich_core::SterilePoolCandidateV1>,
    bootstrap_root: &Path,
) -> anyhow::Result<LeaseResponse> {
    let metadata = ResidentProcessTaskMetadata::from_lease(&lease)?;
    let process_id = metadata.process_id;
    let generation = metadata.generation;
    let fence = ResidentLeaseFence {
        lease_id: lease.id,
        process_id,
        generation,
    };
    let name = metadata.name;
    let run_as_uid = resident_process_run_as_uid(&name);
    let argv: Vec<String> = serde_json::from_value(
        lease
            .job
            .payload
            .get("argv")
            .cloned()
            .context("resident argv is missing")?,
    )
    .context("resident argv is invalid")?;
    let (program, args) = argv
        .split_first()
        .context("resident argv must contain a program")?;
    let cwd = lease
        .job
        .payload
        .get("cwd")
        .filter(|value| !value.is_null())
        .map(|value| serde_json::from_value::<String>(value.clone()))
        .transpose()
        .context("resident cwd is invalid")?;
    let env = lease
        .job
        .payload
        .get("env")
        .cloned()
        .map(serde_json::from_value::<BTreeMap<String, String>>)
        .transpose()
        .context("resident env is invalid")?
        .unwrap_or_default();
    let restart_policy: ResidentProcessRestartPolicy = serde_json::from_value(
        lease
            .job
            .payload
            .get("restartPolicy")
            .cloned()
            .context("resident restart policy is missing")?,
    )
    .context("resident restart policy is invalid")?;
    let expected_sha256 = lease
        .job
        .payload
        .get("bootstrapSha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let sterile_activation_fence = lease
        .job
        .payload
        .get("sterileActivation")
        .cloned()
        .map(serde_json::from_value::<sandboxwich_core::SterileResidentActivationFenceV1>)
        .transpose()
        .context("resident sterile activation fence is invalid")?;
    if let Some(fence) = sterile_activation_fence {
        anyhow::ensure!(
            fence.cell_id.0 == sandbox_id.0,
            "resident sterile activation cell does not match this sandbox"
        );
    }

    let mut delivered_sterile_activation = None;
    let mut delivered_bootstrap = None;
    let mut validated_activation_lease = None;

    if let Some(expected_sha256) = expected_sha256 {
        let bootstrap: ResidentProcessBootstrapReadResponse = decode_json(
            client
                .post(format!("{api}/resident-processes/{process_id}/bootstrap"))
                .json(&ResidentProcessBootstrapReadRequest {
                    generation,
                    lease_id: lease.id.0,
                    expected_sha256,
                })
                .send()
                .await?,
        )
        .await?;
        validated_activation_lease = validate_resident_sterile_activation(
            client,
            api,
            sandbox_id,
            sterile_activation_fence.as_ref(),
            sterile_cell_lease.as_ref(),
            sterile_pool_candidate.as_ref(),
            bootstrap.sterile_activation.as_ref(),
        )
        .await?;
        delivered_sterile_activation = bootstrap.sterile_activation.clone();
        let mut launcher_bootstrap = bootstrap.clone();
        launcher_bootstrap.sterile_activation = None;
        delivered_bootstrap = Some(launcher_bootstrap);
        if sterile_pool_candidate.is_some() {
            // The trusted control sidecar must never materialize the tenant
            // bootstrap in its own filesystem; only the credential-free
            // launcher consumes it from the one-shot tmpfs handoff.
            continue_candidate_bootstrap_validation(&bootstrap)?;
        } else {
            let prepare = prepare_resident_bootstrap_file(&bootstrap, bootstrap_root, run_as_uid);
            if let Err(error) = prepare {
                return fail_lease_terminal(
                    client,
                    api,
                    lease.id,
                    format!("resident bootstrap preparation failed after delivery: {error:#}"),
                )
                .await
                .map_err(Into::into);
            }
        }
    }

    if let Some(candidate) = sterile_pool_candidate.as_ref() {
        validated_activation_lease
            .as_ref()
            .context("candidate activation did not yield a validated live lease")?;
        let bootstrap = delivered_bootstrap
            .context("candidate activation did not deliver its one-shot bootstrap")?;
        // The bootstrap read may race lease revocation/expiry. Revalidate the
        // bearer authority at the final control-side boundary and send only
        // the non-attestation activation over the dedicated mTLS channel.
        let (activation_client, activation_url) = sterile_activation_http_client()?;
        let fence = sterile_activation_fence
            .as_ref()
            .context("candidate job lost activation fence")?;
        let activation = delivered_sterile_activation
            .as_ref()
            .context("candidate bootstrap lost sterile activation")?;
        let expires_at = activate_sterile_launcher_after_revalidation(
            client,
            api,
            sandbox_id,
            fence,
            sterile_cell_lease.as_ref(),
            candidate,
            activation,
            &activation_client,
            &activation_url,
            argv,
            cwd,
            env,
            bootstrap,
        )
        .await?;
        return supervise_sterile_launcher(
            client,
            api,
            lease,
            process_id,
            generation,
            candidate.clone(),
            activation_client,
            activation_url,
            expires_at,
        )
        .await;
    }

    let cancellation = LeaseCancellation::new();
    let renew_task = LeaseRenewalTask::new(spawn_lease_renewal_task(
        client.clone(),
        api.to_string(),
        &lease,
        cancellation.clone(),
    ));
    // Keep every fallible observation/spawn/wait/terminal API call inside one
    // result boundary. Regardless of which `?` exits this block, the renewal
    // handle below is always aborted and awaited before this task is reaped.
    let result = async {
        let max_attempts = if restart_policy == ResidentProcessRestartPolicy::OnFailure {
            3
        } else {
            1
        };
        let mut last_exit_code = None;
        for attempt in 1..=max_attempts {
            validate_resident_sterile_activation(
                client,
                api,
                sandbox_id,
                sterile_activation_fence.as_ref(),
                sterile_cell_lease.as_ref(),
                sterile_pool_candidate.as_ref(),
                delivered_sterile_activation.as_ref(),
            )
            .await?;
            let mut command = TokioProcessCommand::new(program);
            command.args(args).envs(&env);
            if let Some(cwd) = &cwd {
                command.current_dir(cwd);
            }
            command
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .kill_on_drop(true);
            apply_resident_process_run_as_uid(&mut command, run_as_uid);
            let mut child = match command.spawn().context("failed to spawn resident process") {
                Ok(child) => child,
                Err(error) => {
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
                        continue;
                    }
                    // Bootstrap bytes are consumed when this terminal
                    // observation is acknowledged. A subsequent lease cannot
                    // fetch them again, so this final spawn failure must be
                    // terminal rather than advertising a retry that cannot
                    // make progress.
                    let error_message = error.to_string();
                    if let Err(reason) = post_resident_observation_until_resolved(
                        client,
                        api,
                        process_id,
                        ResidentProcessObservationRequest {
                            generation,
                            lease_id: lease.id.0,
                            observed_state: ResidentProcessObservedState::Failed,
                            pid: None,
                            exit_code: None,
                            error_code: Some("resident_process_spawn_failed".into()),
                            error_message: Some(error_message.clone()),
                            provider_pod_name: sterile_pool_candidate
                                .as_ref()
                                .and_then(|candidate| candidate.pod_name.clone()),
                            provider_pod_uid: sterile_pool_candidate
                                .as_ref()
                                .and_then(|candidate| candidate.pod_uid.clone()),
                        },
                        &cancellation,
                    )
                    .await
                    {
                        return reconcile_resident_cancellation_without_child(
                            client, api, fence, reason,
                        )
                        .await;
                    }
                    return fail_lease_terminal(client, api, lease.id, error_message)
                        .await
                        .map_err(Into::into);
                }
            };
            let pid = child.id();
            if let Err(reason) = post_resident_observation_until_resolved(
                client,
                api,
                process_id,
                ResidentProcessObservationRequest {
                    generation,
                    lease_id: lease.id.0,
                    observed_state: ResidentProcessObservedState::Starting,
                    pid,
                    exit_code: None,
                    error_code: None,
                    error_message: None,
                    provider_pod_name: sterile_pool_candidate
                        .as_ref()
                        .and_then(|candidate| candidate.pod_name.clone()),
                    provider_pod_uid: sterile_pool_candidate
                        .as_ref()
                        .and_then(|candidate| candidate.pod_uid.clone()),
                },
                &cancellation,
            )
            .await
            {
                return reconcile_resident_cancellation(
                    client, api, fence, pid, &mut child, reason,
                )
                .await;
            }
            if let Err(reason) = post_resident_observation_until_resolved(
                client,
                api,
                process_id,
                ResidentProcessObservationRequest {
                    generation,
                    lease_id: lease.id.0,
                    observed_state: ResidentProcessObservedState::Running,
                    pid,
                    exit_code: None,
                    error_code: None,
                    error_message: None,
                    provider_pod_name: sterile_pool_candidate
                        .as_ref()
                        .and_then(|candidate| candidate.pod_name.clone()),
                    provider_pod_uid: sterile_pool_candidate
                        .as_ref()
                        .and_then(|candidate| candidate.pod_uid.clone()),
                },
                &cancellation,
            )
            .await
            {
                return reconcile_resident_cancellation(
                    client, api, fence, pid, &mut child, reason,
                )
                .await;
            }
            let status = tokio::select! {
                result = child.wait() => result.context("failed to wait for resident process")?,
                () = wait_for_lease_cancellation(&cancellation) => {
                    return reconcile_resident_cancellation(
                        client,
                        api,
                        fence,
                        pid,
                        &mut child,
                        cancellation.reason(),
                    )
                    .await;
                }
            };
            last_exit_code = status.code();
            if status.success() || attempt == max_attempts {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
        }
        let observed_state = if last_exit_code == Some(0) {
            ResidentProcessObservedState::Stopped
        } else {
            ResidentProcessObservedState::Failed
        };
        if let Err(reason) = post_resident_observation_until_resolved(
            client,
            api,
            process_id,
            ResidentProcessObservationRequest {
                generation,
                lease_id: lease.id.0,
                observed_state,
                pid: None,
                exit_code: last_exit_code,
                error_code: (last_exit_code != Some(0)).then(|| "resident_process_exit".into()),
                error_message: None,
                provider_pod_name: sterile_pool_candidate
                    .as_ref()
                    .and_then(|candidate| candidate.pod_name.clone()),
                provider_pod_uid: sterile_pool_candidate
                    .as_ref()
                    .and_then(|candidate| candidate.pod_uid.clone()),
            },
            &cancellation,
        )
        .await
        {
            return reconcile_resident_cancellation_without_child(client, api, fence, reason).await;
        }
        match complete_resident_lease_until_resolved(
            client,
            api,
            fence,
            last_exit_code,
            &cancellation,
        )
        .await
        {
            Ok(response) => Ok(response),
            Err(reason) => {
                reconcile_resident_cancellation_without_child(client, api, fence, reason).await
            }
        }
    }
    .await;
    renew_task.abort_and_wait().await;
    result
}

async fn execute_streaming(
    request: AgentCommandRequest,
    client: Option<&reqwest::Client>,
    api: Option<&str>,
    lease_id: Option<LeaseId>,
    max_captured_output_bytes: u64,
    cancellation: Option<LeaseCancellation>,
) -> anyhow::Result<AgentCommandResult> {
    validate_agent_command_request(&request)?;
    let AgentCommandRequest {
        argv,
        cwd,
        env,
        stdin,
        timeout_secs,
    } = request;
    let Some((program, args)) = argv.split_first() else {
        bail!("argv must contain at least one item");
    };
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_COMMAND_TIMEOUT_SECS));

    let started_at = Utc::now();
    let mut command = TokioProcessCommand::new(program);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.envs(env);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }

    let mut child = command.spawn().context("failed to execute command")?;
    let stdin_task = match stdin {
        Some(bytes) => {
            let mut pipe = child.stdin.take().context("failed to open command stdin")?;
            Some(tokio::spawn(async move {
                pipe.write_all(&bytes).await?;
                Ok::<_, std::io::Error>(())
            }))
        }
        None => None,
    };
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
    // `cancellation` alongside it means a command also gets killed promptly if
    // `handle_lease`'s background renewal task loses the lease, instead of
    // continuing to run to completion (and possibly being re-queued and
    // executed a second time elsewhere) against a lease we can no longer
    // prove is still ours.
    let wait_for_cancellation = async {
        match &cancellation {
            Some(cancellation) => wait_for_lease_cancellation(cancellation).await,
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

    if status.success()
        && let Some(stdin_task) = stdin_task
    {
        stdin_task
            .await
            .context("command stdin writer task failed")?
            .context("failed to write command stdin")?;
    }
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
    let mut checks = serde_json::json!({
        "exec": {"status": "ok"},
        "files": {"status": "ok"}
    });
    checks
        .as_object_mut()
        .expect("guest health checks are constructed as an object")
        .insert(
            GUEST_AGENT_CAPABILITY_REPORT_CHECK.to_string(),
            serde_json::to_value(GuestAgentCapabilityReport::current())
                .map_err(AgentRequestError::Decode)?,
        );
    let response = client
        .post(format!("{api}/sandboxes/{sandbox_id}/guest-health"))
        .json(&UpdateGuestHealthRequest {
            status,
            agent_version: Some(agent_version()),
            checks: Some(checks),
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
    let stdin = payload
        .get("stdin")
        .cloned()
        .map(|value| {
            serde_json::from_value(serde_json::json!({
                "argv": [],
                "cwd": null,
                "env": {},
                "stdin": value,
                "timeout_secs": null
            }))
            .map(|request: AgentCommandRequest| request.stdin)
        })
        .transpose()
        .map_err(|error| {
            if error.to_string().contains("command_stdin_too_large") {
                anyhow::anyhow!("command_stdin_too_large: command stdin exceeds 1048576 bytes")
            } else {
                anyhow::Error::new(error).context("job payload stdin is invalid")
            }
        })?
        .flatten();
    let timeout_secs = payload.get("timeoutSecs").and_then(|value| value.as_u64());
    let request = AgentCommandRequest {
        argv,
        cwd,
        env,
        stdin,
        timeout_secs,
    };
    validate_agent_command_request(&request)?;
    Ok(request)
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
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose, SanType, string::Ia5String,
    };
    use sandboxwich_core::{
        SterileCellId, SterileCellReleaseTrustClassV1, SterileCellRuntimeClass,
    };
    use std::sync::atomic::AtomicBool;

    use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
    use tokio::net::TcpListener;

    /// Writes `contents` to a fresh, uniquely-named temp file and returns its
    /// path. Mirrors the temp-file-per-test pattern `sandboxwich-worker`'s
    /// provider tests use for their fake `kubectl` script, so tests can run
    /// in parallel without colliding on a shared path.
    fn write_temp_file(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("sandboxwich-agent-test-{}", Uuid::new_v4()));
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    #[tokio::test]
    async fn sterile_lease_gate_preserves_the_cold_path_when_unconfigured() {
        validate_sterile_lease_gate(&reqwest::Client::new(), "http://127.0.0.1:1", None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sterile_lease_gate_rejects_partial_bootstrap_before_network_access() {
        let error = SterileLeaseGateArgs {
            lease_id: Some(Uuid::now_v7()),
            ..Default::default()
        }
        .into_bootstrap()
        .unwrap_err();
        assert!(error.to_string().contains("requires lease id"));
    }

    #[tokio::test]
    async fn sterile_lease_gate_validates_a_complete_live_bootstrap() {
        async fn validate(
            State(lease): State<sandboxwich_core::SterileCellLeaseV1>,
            Json(request): Json<ValidateSterileCellLeaseRequestV1>,
        ) -> Json<ValidateSterileCellLeaseResponseV1> {
            assert_eq!(request.generation, lease.generation);
            assert_eq!(request.organization_id, lease.organization_id);
            assert_eq!(request.workspace_id, lease.workspace_id);
            assert_eq!(request.thread_id, lease.thread_id);
            assert_eq!(request.runner_session_id, lease.runner_session_id);
            assert_eq!(request.lease_attestation, "swla1_test");
            Json(ValidateSterileCellLeaseResponseV1 { ok: true, lease })
        }

        let lease_id = Uuid::now_v7();
        let generation = 2;
        let lease = sandboxwich_core::SterileCellLeaseV1 {
            lease_id,
            cell_id: sandboxwich_core::SterileCellId::new(),
            generation,
            release: sandboxwich_core::SterileCellReleaseTrustClassV1 {
                release_set_id: "release-set-test".into(),
                runtime_class: sandboxwich_core::SterileCellRuntimeClass::KataMicrovm,
                policy_digest: "a".repeat(64),
                signature: "swrs1_test".into(),
            },
            organization_id: "org-1".into(),
            workspace_id: "workspace-1".into(),
            thread_id: "thread-1".into(),
            runner_session_id: "session-1".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/sterile-cell-leases/{lease_id}/validate", post(validate))
            .with_state(lease);
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let attestation_file = write_temp_file("swla1_test\n");
        validate_sterile_lease_gate(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            Some(SterileLeaseBootstrap {
                lease_id,
                generation,
                attestation_file,
                organization_id: "org-1".into(),
                workspace_id: "workspace-1".into(),
                thread_id: "thread-1".into(),
                runner_session_id: "session-1".into(),
            }),
        )
        .await
        .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn sterile_lease_gate_rejects_oversized_attestation_before_network_access() {
        let attestation_file = write_temp_file(&"x".repeat(1025));
        let error = validate_sterile_lease_gate(
            &reqwest::Client::new(),
            "http://127.0.0.1:1",
            Some(SterileLeaseBootstrap {
                lease_id: Uuid::now_v7(),
                generation: 2,
                attestation_file,
                organization_id: "org-1".into(),
                workspace_id: "workspace-1".into(),
                thread_id: "thread-1".into(),
                runner_session_id: "session-1".into(),
            }),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("oversized"));
    }

    #[tokio::test]
    async fn prewarmed_daemon_rejects_activation_expired_at_final_pre_bundle_validation() {
        async fn validate(
            State(lease): State<sandboxwich_core::SterileCellLeaseV1>,
        ) -> Json<ValidateSterileCellLeaseResponseV1> {
            Json(ValidateSterileCellLeaseResponseV1 { ok: true, lease })
        }
        let sandbox_id = SandboxId::new();
        let lease_id = Uuid::now_v7();
        let generation = 2;
        let lease = sandboxwich_core::SterileCellLeaseV1 {
            lease_id,
            cell_id: SterileCellId(sandbox_id.0),
            generation,
            release: SterileCellReleaseTrustClassV1 {
                release_set_id: "release-set-test".into(),
                runtime_class: SterileCellRuntimeClass::KataMicrovm,
                policy_digest: "a".repeat(64),
                signature: "swrs1_test".into(),
            },
            organization_id: "org-1".into(),
            workspace_id: "workspace-1".into(),
            thread_id: "thread-1".into(),
            runner_session_id: "session-1".into(),
            expires_at: Utc::now() - chrono::Duration::seconds(1),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/sterile-cell-leases/{lease_id}/validate", post(validate))
            .with_state(lease);
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let error = validate_resident_sterile_activation(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            sandbox_id,
            Some(&sandboxwich_core::SterileResidentActivationFenceV1 {
                cell_id: SterileCellId(sandbox_id.0),
                lease_id,
                generation,
            }),
            None,
            Some(&sandboxwich_core::SterilePoolCandidateV1 {
                cell_id: SterileCellId(sandbox_id.0),
                release: SterileCellReleaseTrustClassV1 {
                    release_set_id: "release-set-test".into(),
                    runtime_class: SterileCellRuntimeClass::KataMicrovm,
                    policy_digest: "a".repeat(64),
                    signature: "swrs1_test".into(),
                },
                agent_image: format!("agent@sha256:{}", "b".repeat(64)),
                maestro_image: format!("maestro@sha256:{}", "c".repeat(64)),
                service_name: format!("sandboxwich-mc-{sandbox_id}"),
                pod_name: Some(format!("sandboxwich-{sandbox_id}")),
                pod_uid: Some("pod-uid-test".into()),
            }),
            Some(&sandboxwich_core::SterileResidentActivationV1 {
                lease_id,
                generation,
                organization_id: "org-1".into(),
                workspace_id: "workspace-1".into(),
                thread_id: "thread-1".into(),
                runner_session_id: "session-1".into(),
                lease_attestation: "raw-secret-attestation".into(),
            }),
        )
        .await
        .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("expired"));
    }

    #[tokio::test]
    async fn revocation_between_bootstrap_read_and_final_validation_sends_no_activation() {
        async fn validate(
            State((lease, calls)): State<(
                sandboxwich_core::SterileCellLeaseV1,
                Arc<std::sync::atomic::AtomicUsize>,
            )>,
        ) -> Json<ValidateSterileCellLeaseResponseV1> {
            let mut lease = lease;
            if calls.fetch_add(1, Ordering::SeqCst) > 0 {
                lease.expires_at = Utc::now() - chrono::Duration::seconds(1);
            }
            Json(ValidateSterileCellLeaseResponseV1 { ok: true, lease })
        }
        let sandbox_id = SandboxId::new();
        let lease_id = Uuid::now_v7();
        let release = SterileCellReleaseTrustClassV1 {
            release_set_id: "release-set-test".into(),
            runtime_class: SterileCellRuntimeClass::KataMicrovm,
            policy_digest: "a".repeat(64),
            signature: "swrs1_test".into(),
        };
        let lease = sandboxwich_core::SterileCellLeaseV1 {
            lease_id,
            cell_id: SterileCellId(sandbox_id.0),
            generation: 2,
            release: release.clone(),
            organization_id: "org-1".into(),
            workspace_id: "workspace-1".into(),
            thread_id: "thread-1".into(),
            runner_session_id: "session-1".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
        };
        let fence = sandboxwich_core::SterileResidentActivationFenceV1 {
            cell_id: lease.cell_id,
            lease_id,
            generation: lease.generation,
        };
        let candidate = sandboxwich_core::SterilePoolCandidateV1 {
            cell_id: lease.cell_id,
            release,
            agent_image: format!("agent@sha256:{}", "b".repeat(64)),
            maestro_image: format!("maestro@sha256:{}", "c".repeat(64)),
            service_name: format!("sandboxwich-mc-{sandbox_id}"),
            pod_name: Some(format!("sandboxwich-{sandbox_id}")),
            pod_uid: Some("pod-uid-test".into()),
        };
        let activation = sandboxwich_core::SterileResidentActivationV1 {
            lease_id,
            generation: 2,
            organization_id: "org-1".into(),
            workspace_id: "workspace-1".into(),
            thread_id: "thread-1".into(),
            runner_session_id: "session-1".into(),
            lease_attestation: "raw-secret-attestation".into(),
        };
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/sterile-cell-leases/{lease_id}/validate", post(validate))
            .with_state((lease, calls.clone()));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        let api = format!("http://{address}");
        validate_resident_sterile_activation(
            &client,
            &api,
            sandbox_id,
            Some(&fence),
            None,
            Some(&candidate),
            Some(&activation),
        )
        .await
        .expect("initial admission validation succeeds");
        let error = activate_sterile_launcher_after_revalidation(
            &client,
            &api,
            sandbox_id,
            &fence,
            None,
            &candidate,
            &activation,
            &reqwest::Client::new(),
            "https://127.0.0.1:1",
            vec!["/usr/local/bin/maestro".into()],
            None,
            BTreeMap::new(),
            ResidentProcessBootstrapReadResponse {
                ok: true,
                content: b"gateway-token-secret-canary".to_vec(),
                sha256: "hash".into(),
                target_file: "/run/sandboxwich/bootstrap/gateway-token".into(),
                mode: 0o400,
                placement_attestation: None,
                sterile_activation: None,
            },
        )
        .await
        .unwrap_err();
        server.abort();
        assert!(error.to_string().contains("expired"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn sterile_candidate_and_ordinary_agents_reject_opposite_gate_modes() {
        let sandbox_id = SandboxId::new();
        let candidate = sandboxwich_core::SterilePoolCandidateV1 {
            cell_id: SterileCellId(sandbox_id.0),
            release: SterileCellReleaseTrustClassV1 {
                release_set_id: "release-set-test".into(),
                runtime_class: SterileCellRuntimeClass::KataMicrovm,
                policy_digest: "a".repeat(64),
                signature: "swrs1_test".into(),
            },
            agent_image: format!("agent@sha256:{}", "b".repeat(64)),
            maestro_image: format!("maestro@sha256:{}", "c".repeat(64)),
            service_name: format!("sandboxwich-mc-{sandbox_id}"),
            pod_name: Some(format!("sandboxwich-{sandbox_id}")),
            pod_uid: Some("pod-uid-test".into()),
        };
        let candidate_error = validate_resident_sterile_activation(
            &reqwest::Client::new(),
            "http://127.0.0.1:1",
            sandbox_id,
            None,
            None,
            Some(&candidate),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            candidate_error
                .to_string()
                .contains("gated/ungated mismatch")
        );

        let fence = sandboxwich_core::SterileResidentActivationFenceV1 {
            cell_id: candidate.cell_id,
            lease_id: Uuid::now_v7(),
            generation: 2,
        };
        let activation = sandboxwich_core::SterileResidentActivationV1 {
            lease_id: fence.lease_id,
            generation: fence.generation,
            organization_id: "org-1".into(),
            workspace_id: "workspace-1".into(),
            thread_id: "thread-1".into(),
            runner_session_id: "session-1".into(),
            lease_attestation: "raw-secret".into(),
        };
        let ordinary_error = validate_resident_sterile_activation(
            &reqwest::Client::new(),
            "http://127.0.0.1:1",
            sandbox_id,
            Some(&fence),
            None,
            None,
            Some(&activation),
        )
        .await
        .unwrap_err();
        assert!(
            ordinary_error
                .to_string()
                .contains("ordinary agent rejected")
        );
    }

    #[test]
    fn activation_only_handoff_does_not_create_a_bootstrap_file() {
        let root = tempfile::tempdir().unwrap();
        let bootstrap = ResidentProcessBootstrapReadResponse {
            ok: true,
            content: Vec::new(),
            sha256: format!("{:x}", Sha256::digest([])),
            target_file: String::new(),
            mode: 0,
            placement_attestation: None,
            sterile_activation: Some(sandboxwich_core::SterileResidentActivationV1 {
                lease_id: Uuid::now_v7(),
                generation: 2,
                organization_id: "org-1".into(),
                workspace_id: "workspace-1".into(),
                thread_id: "thread-1".into(),
                runner_session_id: "session-1".into(),
                lease_attestation: "raw-secret-attestation".into(),
            }),
        };

        prepare_resident_bootstrap_file(&bootstrap, root.path(), None).unwrap();
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn sterile_launcher_response_loss_replay_is_exactly_idempotent() {
        let state = SterileLauncherServerState {
            activation: Arc::new(Mutex::new(SterileLauncherActivationState::Waiting)),
        };
        let accepted = SterileLauncherStatusV1 {
            phase: SterileLauncherPhaseV1::Accepted,
            pid: None,
            exit_code: None,
            error: None,
        };
        assert!(
            register_sterile_activation(&state, [7; 32], accepted.clone())
                .await
                .unwrap()
                .0
        );
        assert!(
            !register_sterile_activation(&state, [7; 32], accepted.clone())
                .await
                .unwrap()
                .0
        );
        let conflict = register_sterile_activation(&state, [8; 32], accepted)
            .await
            .unwrap_err();
        assert_eq!(conflict.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn sterile_launcher_channel_requires_a_client_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
        let mut client_params = CertificateParams::new(Vec::new()).unwrap();
        let client_uri = "spiffe://sandboxwich.dev/sterile-cell/test/supervisor/test";
        client_params.subject_alt_names =
            vec![SanType::URI(Ia5String::try_from(client_uri).unwrap())];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();
        let mut wrong_client_params = CertificateParams::new(Vec::new()).unwrap();
        wrong_client_params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from("spiffe://sandboxwich.dev/sterile-cell/other/supervisor/other")
                .unwrap(),
        )];
        wrong_client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let wrong_client_key = KeyPair::generate().unwrap();
        let wrong_client_cert = wrong_client_params
            .signed_by(&wrong_client_key, &issuer)
            .unwrap();

        let server_cert_file = directory.path().join("server.crt");
        let server_key_file = directory.path().join("server.key");
        let ca_file = directory.path().join("ca.crt");
        std::fs::write(&server_cert_file, server_cert.pem()).unwrap();
        std::fs::write(&server_key_file, server_key.serialize_pem()).unwrap();
        std::fs::write(&ca_file, ca.pem()).unwrap();
        let tls =
            sterile_launcher_tls_config(&server_cert_file, &server_key_file, &ca_file, client_uri)
                .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = SterileLauncherServerState {
            activation: Arc::new(Mutex::new(SterileLauncherActivationState::Waiting)),
        };
        let app = Router::new()
            .route("/v1/status", get(get_sterile_launcher_status))
            .with_state(state);
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let ca = reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap();
        let without_identity = reqwest::Client::builder()
            .add_root_certificate(ca.clone())
            .build()
            .unwrap();
        assert!(
            without_identity
                .get(format!("https://localhost:{}/v1/status", address.port()))
                .send()
                .await
                .is_err()
        );
        let wrong_identity = format!(
            "{}{}",
            wrong_client_cert.pem(),
            wrong_client_key.serialize_pem()
        );
        let wrong_client = reqwest::Client::builder()
            .identity(reqwest::Identity::from_pem(wrong_identity.as_bytes()).unwrap())
            .add_root_certificate(ca.clone())
            .build()
            .unwrap();
        assert!(
            wrong_client
                .get(format!("https://localhost:{}/v1/status", address.port()))
                .send()
                .await
                .is_err()
        );
        let identity = format!("{}{}", client_cert.pem(), client_key.serialize_pem());
        let authenticated = reqwest::Client::builder()
            .identity(reqwest::Identity::from_pem(identity.as_bytes()).unwrap())
            .add_root_certificate(ca)
            .build()
            .unwrap();
        let response = authenticated
            .get(format!("https://localhost:{}/v1/status", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        handle.shutdown();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sterile_lease_expiry_stops_a_running_daemon() {
        let lease = sandboxwich_core::SterileCellLeaseV1 {
            lease_id: Uuid::now_v7(),
            cell_id: sandboxwich_core::SterileCellId::new(),
            generation: 2,
            release: sandboxwich_core::SterileCellReleaseTrustClassV1 {
                release_set_id: "release-set-test".into(),
                runtime_class: sandboxwich_core::SterileCellRuntimeClass::KataMicrovm,
                policy_digest: "a".repeat(64),
                signature: "swrs1_test".into(),
            },
            organization_id: "org-1".into(),
            workspace_id: "workspace-1".into(),
            thread_id: "thread-1".into(),
            runner_session_id: "session-1".into(),
            expires_at: Utc::now() + chrono::Duration::milliseconds(10),
        };
        let error = run_until_sterile_lease_expiry(
            std::future::pending::<anyhow::Result<()>>(),
            Some(&lease),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("lease expired"));
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
    fn guest_credential_source_prefers_a_provided_token_over_self_minting() {
        let worker_id = Uuid::now_v7();
        let source =
            guest_credential_source(Some("sbw_gtok_provided".to_string()), Some(worker_id), 3600);
        assert_eq!(
            source,
            GuestCredentialSource::Provided("sbw_gtok_provided".to_string())
        );
    }

    #[test]
    fn guest_credential_source_self_mints_when_no_token_is_provided_but_a_worker_id_is() {
        let worker_id = Uuid::now_v7();
        let source = guest_credential_source(None, Some(worker_id), 1800);
        assert_eq!(
            source,
            GuestCredentialSource::SelfMint {
                worker_id,
                ttl_seconds: 1800
            }
        );
    }

    #[test]
    fn guest_credential_source_is_none_without_a_token_or_a_worker_id() {
        // Mirrors `heartbeat`/`exec`, which never have a worker id (there is no
        // lease-claiming loop to scope): nothing to mint against, so the caller
        // falls back to the worker-wide client unchanged.
        let source = guest_credential_source(None, None, 3600);
        assert_eq!(source, GuestCredentialSource::None);
    }

    #[test]
    fn renewal_conflict_preserves_the_resident_desired_stop_reason() {
        let error = AgentRequestError::Status {
            status: reqwest::StatusCode::CONFLICT,
            body: serde_json::to_string(&ErrorEnvelope::new(
                "resident_process_stopped",
                "resident process no longer desires a running lease",
            ))
            .unwrap(),
        };

        assert!(error.is_resident_desired_stop());
        let cancellation = LeaseCancellation::new();
        cancellation.cancel(if error.is_resident_desired_stop() {
            LeaseCancellationReason::DesiredStop
        } else {
            LeaseCancellationReason::LeaseLost
        });
        assert_eq!(cancellation.reason(), LeaseCancellationReason::DesiredStop);
    }

    #[derive(Clone)]
    struct BootstrapSpawnFailureState {
        bootstrap: ResidentProcessBootstrapReadResponse,
        lease: sandboxwich_core::JobLease,
        bootstrap_read: Arc<AtomicBool>,
        terminal_fail_posted: Arc<AtomicBool>,
        observations: Arc<std::sync::Mutex<Vec<ResidentProcessObservedState>>>,
    }

    async fn test_read_bootstrap(
        State(state): State<BootstrapSpawnFailureState>,
    ) -> Json<ResidentProcessBootstrapReadResponse> {
        state.bootstrap_read.store(true, Ordering::SeqCst);
        Json(state.bootstrap)
    }

    async fn test_observe_bootstrap_spawn_failure(
        State(state): State<BootstrapSpawnFailureState>,
        Json(request): Json<ResidentProcessObservationRequest>,
    ) -> StatusCode {
        state
            .observations
            .lock()
            .expect("observations lock")
            .push(request.observed_state);
        StatusCode::NO_CONTENT
    }

    async fn test_terminal_fail_bootstrap_spawn_failure(
        State(state): State<BootstrapSpawnFailureState>,
        Json(request): Json<FailLeaseRequest>,
    ) -> Json<LeaseResponse> {
        assert!(!request.retry, "consumed bootstrap must not be retried");
        state.terminal_fail_posted.store(true, Ordering::SeqCst);
        Json(LeaseResponse {
            ok: true,
            lease: state.lease,
        })
    }

    #[tokio::test]
    async fn bootstrap_delivery_followed_by_spawn_failure_reports_failed_without_starting() {
        let bootstrap_root = TempWorkspace::new();
        let target = bootstrap_root.path().join("orb-sidecar-bootstrap");
        let worker_id = sandboxwich_core::WorkerId::new();
        let process_id = ResidentProcessId(Uuid::now_v7());
        let now = Utc::now();
        let job = test_job(
            JobKind::RunResidentProcess,
            serde_json::json!({
                "residentProcessId": process_id,
                "generation": 1,
                "name": "orb-executor",
                "argv": ["/definitely/missing/sandboxwich-resident"],
                "restartPolicy": ResidentProcessRestartPolicy::Never,
                "bootstrapSha256": "test-bootstrap-sha",
            }),
        );
        let lease = sandboxwich_core::JobLease {
            id: LeaseId::new(),
            job_id: job.id,
            worker_id,
            status: sandboxwich_core::LeaseStatus::Active,
            attempt: 1,
            leased_at: now,
            expires_at: now + chrono::Duration::seconds(60),
            completed_at: None,
            error: None,
            required_execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
            job,
        };
        let state = BootstrapSpawnFailureState {
            bootstrap: ResidentProcessBootstrapReadResponse {
                ok: true,
                content: b"bootstrap".to_vec(),
                sha256: "test-bootstrap-sha".into(),
                target_file: target.to_string_lossy().into_owned(),
                mode: 0o600,
                placement_attestation: None,
                sterile_activation: None,
            },
            lease: lease.clone(),
            bootstrap_read: Arc::new(AtomicBool::new(false)),
            terminal_fail_posted: Arc::new(AtomicBool::new(false)),
            observations: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route(
                "/resident-processes/{process_id}/bootstrap",
                post(test_read_bootstrap),
            )
            .route(
                "/resident-processes/{process_id}/observations",
                post(test_observe_bootstrap_spawn_failure),
            )
            .route(
                "/leases/{lease_id}/fail",
                post(test_terminal_fail_bootstrap_spawn_failure),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let response = handle_resident_process_with_bootstrap_root(
            &client,
            &format!("http://{address}"),
            SandboxId::new(),
            lease,
            None,
            None,
            bootstrap_root.path(),
        )
        .await
        .expect("the acknowledged terminal spawn failure must reconcile its current lease");
        server.abort();

        assert!(response.ok);
        assert!(state.bootstrap_read.load(Ordering::SeqCst));
        assert!(state.terminal_fail_posted.load(Ordering::SeqCst));
        assert_eq!(
            state
                .observations
                .lock()
                .expect("observations lock")
                .as_slice(),
            [ResidentProcessObservedState::Failed],
            "a delivered bootstrap must be terminally acknowledged as Failed; Starting cannot be acknowledged \
             before the fallible spawn succeeds"
        );
    }

    #[tokio::test]
    async fn bootstrap_delivery_followed_by_file_collision_is_terminal() {
        let bootstrap_root = TempWorkspace::new();
        let target = bootstrap_root.path().join("existing-bootstrap");
        std::fs::write(&target, b"must-not-be-overwritten").unwrap();
        let worker_id = sandboxwich_core::WorkerId::new();
        let process_id = ResidentProcessId(Uuid::now_v7());
        let now = Utc::now();
        let job = test_job(
            JobKind::RunResidentProcess,
            serde_json::json!({
                "residentProcessId": process_id,
                "generation": 1,
                "name": "orb-executor",
                "argv": ["/bin/true"],
                "restartPolicy": ResidentProcessRestartPolicy::Never,
                "bootstrapSha256": "test-bootstrap-sha",
            }),
        );
        let lease = sandboxwich_core::JobLease {
            id: LeaseId::new(),
            job_id: job.id,
            worker_id,
            status: sandboxwich_core::LeaseStatus::Active,
            attempt: 1,
            leased_at: now,
            expires_at: now + chrono::Duration::seconds(60),
            completed_at: None,
            error: None,
            required_execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
            job,
        };
        let state = BootstrapSpawnFailureState {
            bootstrap: ResidentProcessBootstrapReadResponse {
                ok: true,
                content: b"bootstrap".to_vec(),
                sha256: "test-bootstrap-sha".into(),
                target_file: target.to_string_lossy().into_owned(),
                mode: 0o600,
                placement_attestation: None,
                sterile_activation: None,
            },
            lease: lease.clone(),
            bootstrap_read: Arc::new(AtomicBool::new(false)),
            terminal_fail_posted: Arc::new(AtomicBool::new(false)),
            observations: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route(
                "/resident-processes/{process_id}/bootstrap",
                post(test_read_bootstrap),
            )
            .route(
                "/leases/{lease_id}/fail",
                post(test_terminal_fail_bootstrap_spawn_failure),
            )
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let response = handle_resident_process_with_bootstrap_root(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            SandboxId::new(),
            lease,
            None,
            None,
            bootstrap_root.path(),
        )
        .await
        .expect("post-delivery file failures must terminally reconcile the current lease");
        server.abort();

        assert!(response.ok);
        assert!(state.bootstrap_read.load(Ordering::SeqCst));
        assert!(state.terminal_fail_posted.load(Ordering::SeqCst));
        assert_eq!(std::fs::read(target).unwrap(), b"must-not-be-overwritten");
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
            stdin: None,
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
    async fn command_stdin_reaches_guest_but_not_result_debug_or_serialization() {
        let marker = b"apex-private-input".to_vec();
        let request = AgentCommandRequest {
            argv: vec!["sh".to_string(), "-c".to_string(), "sha256sum".to_string()],
            cwd: None,
            env: BTreeMap::new(),
            stdin: Some(marker),
            timeout_secs: Some(5),
        };

        let debug = format!("{request:?}");
        let serialized = serde_json::to_string(&request).expect("request should serialize");
        let result = execute_streaming(
            request,
            None,
            None,
            None,
            DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
            None,
        )
        .await
        .expect("stdin hashing command should complete");

        assert!(
            result
                .stdout
                .contains("f825ba6c6c1ddd75498ea957ba3e31ab2f3b8855baa87fe32197e14096e553c2")
        );
        for rendering in [debug, serialized, serde_json::to_string(&result).unwrap()] {
            assert!(!rendering.contains("apex-private-input"));
        }
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
            stdin: None,
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
            stdin: None,
            timeout_secs: Some(60), // Long enough that the timeout branch can't win the race.
        };
        let cancellation = LeaseCancellation::new();
        let flip_cancellation = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            flip_cancellation.cancel(LeaseCancellationReason::LeaseLost);
        });

        let started = std::time::Instant::now();
        let error = execute_streaming(
            request,
            None,
            None,
            None,
            DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
            Some(cancellation),
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

    #[tokio::test]
    async fn dropping_lease_owner_aborts_detached_renewal_task() {
        let reached_after_drop = Arc::new(AtomicBool::new(false));
        let reached = reached_after_drop.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            reached.store(true, Ordering::SeqCst);
        });
        let abort_handle = handle.abort_handle();
        let renewal = LeaseRenewalTask::new(handle);

        drop(renewal);
        for _ in 0..10 {
            if abort_handle.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert!(
            abort_handle.is_finished(),
            "dropping the lease owner must not detach its renewal task"
        );
        assert!(!reached_after_drop.load(Ordering::SeqCst));
    }

    fn test_job(kind: JobKind, payload: serde_json::Value) -> sandboxwich_core::Job {
        sandboxwich_core::Job {
            id: sandboxwich_core::JobId::new(),
            tenant_id: "default".to_string(),
            kind,
            status: sandboxwich_core::JobStatus::Leased,
            payload,
            required_capability: sandboxwich_core::WorkerCapability::RunCommand,
            required_execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
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
    fn lease_scope_violation_accepts_a_resident_process_for_its_own_sandbox() {
        let sandbox_id = SandboxId(Uuid::now_v7());
        let job = test_job(
            JobKind::RunResidentProcess,
            serde_json::json!({
                "sandboxId": sandbox_id,
                "residentProcessId": Uuid::now_v7(),
                "generation": 1,
                "argv": ["/usr/local/bin/orb-executor"]
            }),
        );

        assert_eq!(lease_scope_violation(&job, sandbox_id), None);
    }

    #[test]
    fn full_resident_supervisor_leaves_resident_work_queued() {
        assert_eq!(guest_claim_kinds(false, false), vec![JobKind::RunCommand]);
        assert_eq!(
            guest_claim_kinds(true, false),
            vec![JobKind::RunCommand, JobKind::RunResidentProcess]
        );
        assert!(guest_claim_kinds(false, true).is_empty());
        assert_eq!(
            guest_claim_kinds(true, true),
            vec![JobKind::RunResidentProcess]
        );
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

    /// Runs `id -u` and returns the reported uid. Used instead of a `libc`
    /// dependency just for `geteuid()`; `id` is present on every platform
    /// this daemon targets (Linux sandbox images and macOS dev machines).
    fn current_uid() -> u32 {
        let output = std::process::Command::new("id")
            .arg("-u")
            .output()
            .expect("run `id -u`");
        assert!(output.status.success(), "`id -u` must succeed");
        String::from_utf8(output.stdout)
            .expect("id -u output is utf8")
            .trim()
            .parse()
            .expect("id -u output is a uid")
    }

    #[tokio::test]
    async fn orb_executor_run_as_uid_is_none_and_never_shifts_identity() {
        // orb-executor (and every unrecognized resident-process name) must
        // resolve to `None` -- no privilege drop attempt, inheriting
        // whatever uid the agent process itself runs as. This is the
        // pre-#176 behavior and must not regress.
        assert_eq!(
            sandboxwich_core::resident_process_run_as_uid(
                sandboxwich_core::ORB_EXECUTOR_RESIDENT_PROCESS_NAME
            ),
            None
        );
        let mut command = TokioProcessCommand::new("id");
        command.arg("-u");
        apply_resident_process_run_as_uid(&mut command, None);
        let output = command.output().await.expect("spawn `id -u` unmodified");
        assert!(output.status.success());
        let reported: u32 = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(
            reported,
            current_uid(),
            "orb-executor must inherit the agent's own uid, not shift identity"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn orb_sidecar_run_as_uid_actually_attempts_privilege_separation() {
        // The uid #176 assigns orb-sidecar must be a fixed value, distinct
        // from every resident process that leaves `run_as_uid` at `None`.
        let sidecar_uid = sandboxwich_core::resident_process_run_as_uid(
            sandboxwich_core::ORB_SIDECAR_RESIDENT_PROCESS_NAME,
        )
        .expect("orb-sidecar must get an explicit run-as uid");
        assert_eq!(
            sidecar_uid,
            sandboxwich_core::ORB_SIDECAR_RESIDENT_PROCESS_UID
        );

        let euid = current_uid();
        let mut command = TokioProcessCommand::new("id");
        command.arg("-u");
        apply_resident_process_run_as_uid(&mut command, Some(sidecar_uid));
        let result = command.output().await;

        if euid == 0 {
            // Running as root: setuid must actually succeed and the child
            // must observe the sidecar's uid, not root's -- proving uid
            // separation genuinely takes effect when the agent has the
            // privilege to apply it (mirrors what an apex-supervisor-style
            // pod, granted SETUID/SETGID, would experience in production).
            let output = result.expect("root can spawn under an arbitrary uid");
            assert!(output.status.success());
            let reported: u32 = String::from_utf8(output.stdout)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert_eq!(
                reported, sidecar_uid,
                "sidecar child must run as the sidecar uid, not root's"
            );
        } else {
            // The common case: an unprivileged agent (no SETUID/SETGID
            // capability, e.g. today's default non-apex sandbox pod running
            // as uid 10001) cannot drop to an arbitrary different uid.
            // Fail-closed proof: the spawn must fail outright -- it must
            // NEVER silently fall back to running the sidecar under the
            // agent's own uid, which would make v1's uid-separation claim a
            // lie for anyone who forgot to grant the capability.
            assert_ne!(
                sidecar_uid, euid,
                "test fixture requires a target uid distinct from the current uid"
            );
            let error = result.expect_err(
                "spawning under a different uid without SETUID/SETGID must fail, not silently \
                 run the sidecar under the caller's own uid",
            );
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "unexpected error kind for an unprivileged uid switch: {error:?}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn orb_sidecar_can_read_its_private_bootstrap_after_uid_transfer() {
        use std::os::unix::fs::OpenOptionsExt;

        if current_uid() != 0 {
            return;
        }
        let sidecar_uid = sandboxwich_core::ORB_SIDECAR_RESIDENT_PROCESS_UID;
        let target = std::env::temp_dir().join(format!(
            "sandboxwich-sidecar-bootstrap-{}",
            uuid::Uuid::new_v4()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
            .expect("create private sidecar bootstrap");
        file.write_all(b"sidecar-bootstrap-canary")
            .expect("write sidecar bootstrap");
        file.sync_all().expect("sync sidecar bootstrap");
        transfer_resident_bootstrap_ownership(&file, Some(sidecar_uid))
            .expect("transfer bootstrap to sidecar uid");
        drop(file);

        let mut command = TokioProcessCommand::new("cat");
        command.arg(&target);
        apply_resident_process_run_as_uid(&mut command, Some(sidecar_uid));
        let output = command
            .output()
            .await
            .expect("uid-isolated sidecar reads its bootstrap");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"sidecar-bootstrap-canary");
        std::fs::remove_file(target).expect("remove sidecar bootstrap fixture");
    }

    fn test_agent_activation() -> sandboxwich_core::AgentSandboxActivationV1 {
        sandboxwich_core::AgentSandboxActivationV1 {
            version: sandboxwich_core::AgentSandboxActivationV1::VERSION,
            claim_uid: "claim".into(),
            sandbox_uid: "sandbox".into(),
            pod_uid: "pod".into(),
            image_digest: "sha256:image".into(),
            bootstrap_digest: "sha256:bootstrap".into(),
            policy_digest: "sha256:policy".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(1),
            nonce: "nonce-1".into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn agent_activation_verifies_with_raw_committed_public_key_bytes() {
        use ring::{rand::SystemRandom, signature::KeyPair};
        let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap();
        let mut activation = test_agent_activation();
        activation.signature =
            BASE64.encode(key.sign(&activation.signing_payload().unwrap()).as_ref());
        let signature = BASE64.decode(&activation.signature).unwrap();
        UnparsedPublicKey::new(&ED25519, key.public_key().as_ref())
            .verify(&activation.signing_payload().unwrap(), &signature)
            .expect("raw 32-byte public key verifies");
    }

    #[test]
    fn agent_activation_rejects_binding_mismatch_expiry_and_unsafe_nonce() {
        let activation = test_agent_activation();
        let expected = [
            ("claim_uid", Some("wrong"), activation.claim_uid.as_str()),
            (
                "sandbox_uid",
                Some("sandbox"),
                activation.sandbox_uid.as_str(),
            ),
            ("pod_uid", Some("pod"), activation.pod_uid.as_str()),
            (
                "image_digest",
                Some("sha256:image"),
                activation.image_digest.as_str(),
            ),
            (
                "bootstrap_digest",
                Some("sha256:bootstrap"),
                activation.bootstrap_digest.as_str(),
            ),
            (
                "policy_digest",
                Some("sha256:policy"),
                activation.policy_digest.as_str(),
            ),
        ];
        assert_eq!(
            validate_agent_sandbox_bindings(&activation, expected)
                .unwrap_err()
                .to_string(),
            "agent_sandbox_activation_claim_uid_mismatch"
        );

        let mut expired = activation.clone();
        expired.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(
            expired.validate_shape(Utc::now()).unwrap_err(),
            "agent_sandbox_activation_expired"
        );

        let mut unsafe_nonce = activation;
        unsafe_nonce.nonce = "../replay".into();
        let expected = [
            ("claim_uid", Some("claim"), unsafe_nonce.claim_uid.as_str()),
            (
                "sandbox_uid",
                Some("sandbox"),
                unsafe_nonce.sandbox_uid.as_str(),
            ),
            ("pod_uid", Some("pod"), unsafe_nonce.pod_uid.as_str()),
            (
                "image_digest",
                Some("sha256:image"),
                unsafe_nonce.image_digest.as_str(),
            ),
            (
                "bootstrap_digest",
                Some("sha256:bootstrap"),
                unsafe_nonce.bootstrap_digest.as_str(),
            ),
            (
                "policy_digest",
                Some("sha256:policy"),
                unsafe_nonce.policy_digest.as_str(),
            ),
        ];
        assert_eq!(
            validate_agent_sandbox_bindings(&unsafe_nonce, expected)
                .unwrap_err()
                .to_string(),
            "agent_sandbox_activation_nonce_invalid"
        );
    }
}
