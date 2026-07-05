use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue, InvalidHeaderValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ApiClientBuildError {
    #[error("invalid SANDBOXWICH_API_TOKEN")]
    InvalidApiToken(#[source] InvalidHeaderValue),
    #[error("invalid SANDBOXWICH_TENANT")]
    InvalidTenant(#[source] InvalidHeaderValue),
    #[error("failed to build HTTP client")]
    Build(#[source] reqwest::Error),
}

pub fn build_api_client(
    api_token: Option<&str>,
    tenant: Option<&str>,
) -> Result<reqwest::Client, ApiClientBuildError> {
    let mut headers = HeaderMap::new();
    if let Some(api_token) = api_token.map(str::trim).filter(|token| !token.is_empty()) {
        let value = format!("Bearer {api_token}");
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&value).map_err(ApiClientBuildError::InvalidApiToken)?,
        );
    }
    if let Some(tenant) = tenant.map(str::trim).filter(|tenant| !tenant.is_empty()) {
        headers.insert(
            HeaderName::from_static("x-sandboxwich-tenant"),
            HeaderValue::from_str(tenant).map_err(ApiClientBuildError::InvalidTenant)?,
        );
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(ApiClientBuildError::Build)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SandboxId(pub Uuid);

impl SandboxId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SandboxId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandId(pub Uuid);

impl CommandId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CommandId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CommandId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandOutputChunkId(pub Uuid);

impl CommandOutputChunkId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CommandOutputChunkId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CommandOutputChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(pub Uuid);

impl EventId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotId(pub Uuid);

impl SnapshotId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SnapshotId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerId(pub Uuid);

impl WorkerId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for WorkerId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for WorkerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(pub Uuid);

impl JobId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseId(pub Uuid);

impl LeaseId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for LeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LeaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SshKeyId(pub Uuid);

impl SshKeyId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SshKeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SshKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DesktopSessionId(pub Uuid);

impl DesktopSessionId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for DesktopSessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DesktopSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuntimeResourceId(pub Uuid);

impl RuntimeResourceId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for RuntimeResourceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RuntimeResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CleanupRunId(pub Uuid);

impl CleanupRunId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CleanupRunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CleanupRunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Planning,
    Provisioning,
    Ready,
    Running,
    Idle,
    Archiving,
    Archived,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Pending,
    Ready,
    Failed,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopSessionStatus {
    Pending,
    Ready,
    Failed,
    Closed,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopAccessMode {
    Browser,
    Vnc,
    Rdp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeResourceKind {
    Pod,
    PersistentVolumeClaim,
    Service,
    VolumeSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeResourcePurpose {
    Runtime,
    Workspace,
    Ssh,
    Desktop,
    Snapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeResourceStatus {
    Planned,
    Applied,
    Ready,
    Failed,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupRunStatus {
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderRuntimeResource {
    pub sandbox_id: SandboxId,
    pub snapshot_id: Option<SnapshotId>,
    pub provider: String,
    pub resource_kind: RuntimeResourceKind,
    pub purpose: RuntimeResourcePurpose,
    pub resource_name: String,
    pub namespace: String,
    pub status: RuntimeResourceStatus,
    pub cluster: Option<String>,
    pub storage_class: Option<String>,
    pub snapshot_class: Option<String>,
    pub storage_size: Option<String>,
    pub runtime_image: Option<String>,
    pub service_port: Option<u16>,
    pub target_port: Option<String>,
    pub source_snapshot_id: Option<SnapshotId>,
    pub ready_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeResource {
    pub id: RuntimeResourceId,
    pub sandbox_id: SandboxId,
    pub snapshot_id: Option<SnapshotId>,
    pub provider: String,
    pub resource_kind: RuntimeResourceKind,
    pub purpose: RuntimeResourcePurpose,
    pub resource_name: String,
    pub namespace: String,
    pub status: RuntimeResourceStatus,
    pub cluster: Option<String>,
    pub storage_class: Option<String>,
    pub snapshot_class: Option<String>,
    pub storage_size: Option<String>,
    pub runtime_image: Option<String>,
    pub service_port: Option<u16>,
    pub target_port: Option<String>,
    pub source_snapshot_id: Option<SnapshotId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub observed_at: Option<DateTime<Utc>>,
    pub last_reconciled_at: Option<DateTime<Utc>>,
    pub ready_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sandbox {
    pub id: SandboxId,
    pub tenant_id: String,
    pub name: String,
    pub state: SandboxState,
    pub template: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ttl_seconds: Option<u64>,
    pub parent_snapshot_id: Option<SnapshotId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateSandboxRequest {
    pub name: Option<String>,
    pub template: Option<String>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxResponse {
    pub ok: bool,
    pub sandbox: Sandbox,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxListResponse {
    pub ok: bool,
    pub sandboxes: Vec<Sandbox>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeResourceListResponse {
    pub ok: bool,
    pub resources: Vec<RuntimeResource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconcileRuntimeResourcesRequest {
    pub provider: String,
    pub namespace: String,
    pub cluster: Option<String>,
    #[serde(default)]
    pub resources: Vec<ProviderRuntimeResource>,
    #[serde(default)]
    pub mark_missing_deleted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconcileRuntimeResourcesResponse {
    pub ok: bool,
    pub observed_at: DateTime<Utc>,
    pub upserted: Vec<RuntimeResource>,
    pub deleted: Vec<RuntimeResource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CleanupRun {
    pub id: CleanupRunId,
    pub status: CleanupRunStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub expired_snapshots: u64,
    pub archived_sandboxes_deleted: u64,
    pub archived_sandboxes_skipped: u64,
    pub runtime_resources_deleted: u64,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub sandbox_id: SandboxId,
    pub status: SnapshotStatus,
    pub label: String,
    pub inventory: serde_json::Value,
    pub provider_metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateSnapshotRequest {
    pub label: Option<String>,
    pub inventory: Option<serde_json::Value>,
    pub provider_metadata: Option<serde_json::Value>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub ok: bool,
    pub snapshot: Snapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotListResponse {
    pub ok: bool,
    pub snapshots: Vec<Snapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotCleanupResponse {
    pub ok: bool,
    pub cleanup_run: CleanupRun,
    pub expired: Vec<Snapshot>,
    pub archived_sandboxes_deleted: u64,
    pub archived_sandboxes: Vec<Sandbox>,
    pub archived_sandboxes_skipped: Vec<ArchivedSandboxCleanupSkip>,
    pub runtime_resources_deleted: Vec<RuntimeResource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchivedSandboxCleanupSkip {
    pub sandbox: Sandbox,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesktopSession {
    pub id: DesktopSessionId,
    pub sandbox_id: SandboxId,
    pub status: DesktopSessionStatus,
    pub broker: String,
    pub broker_url: Option<String>,
    pub access_mode: DesktopAccessMode,
    pub connection_metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateDesktopSessionRequest {
    pub broker: Option<String>,
    pub broker_url: Option<String>,
    pub access_mode: Option<DesktopAccessMode>,
    pub connection_metadata: Option<serde_json::Value>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateDesktopSessionRequest {
    pub status: DesktopSessionStatus,
    pub broker: Option<String>,
    pub broker_url: Option<String>,
    pub access_mode: Option<DesktopAccessMode>,
    pub connection_metadata: Option<serde_json::Value>,
    pub ttl_seconds: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesktopAccessRequest {
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesktopAccess {
    pub session_id: DesktopSessionId,
    pub sandbox_id: SandboxId,
    pub broker: String,
    pub access_mode: DesktopAccessMode,
    pub access_url: String,
    pub expires_at: DateTime<Utc>,
    pub connection_metadata: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesktopSessionResponse {
    pub ok: bool,
    pub desktop_session: DesktopSession,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesktopSessionListResponse {
    pub ok: bool,
    pub desktop_sessions: Vec<DesktopSession>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesktopAccessResponse {
    pub ok: bool,
    pub access: DesktopAccess,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SshAccessRequest {
    pub principal: Option<String>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SshAccess {
    pub sandbox_id: SandboxId,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub principal: String,
    pub command: String,
    pub scp_command_prefix: String,
    pub expires_at: DateTime<Utc>,
    pub connection_metadata: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SshAccessResponse {
    pub ok: bool,
    pub ssh_access: SshAccess,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandRequest {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Queued,
    Running,
    Finished,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandRun {
    pub id: CommandId,
    pub sandbox_id: SandboxId,
    pub status: CommandStatus,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandResponse {
    pub ok: bool,
    pub command: CommandRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandListResponse {
    pub ok: bool,
    pub commands: Vec<CommandRun>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandOutputChunk {
    pub id: CommandOutputChunkId,
    pub command_id: CommandId,
    pub stream: CommandOutputStream,
    pub sequence: u64,
    pub chunk: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppendCommandOutputRequest {
    pub stream: CommandOutputStream,
    pub chunk: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandOutputChunkResponse {
    pub ok: bool,
    pub chunk: CommandOutputChunk,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandOutputListResponse {
    pub ok: bool,
    pub chunks: Vec<CommandOutputChunk>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PromptRequest {
    pub instructions: String,
    pub engine: Option<String>,
    pub model: Option<String>,
    pub effort: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PromptQueuedResponse {
    pub ok: bool,
    pub event: SandboxEvent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxEventKind {
    LifecycleChanged,
    CommandQueued,
    CommandStarted,
    CommandOutput,
    CommandFinished,
    PromptQueued,
    PromptStarted,
    PromptFinished,
    DesktopRequested,
    DesktopReady,
    DesktopFailed,
    DesktopClosed,
    DesktopExpired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxEvent {
    pub id: EventId,
    pub sandbox_id: SandboxId,
    pub kind: SandboxEventKind,
    pub data: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventListResponse {
    pub ok: bool,
    pub events: Vec<SandboxEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    Registered,
    Online,
    Draining,
    Offline,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerCapability {
    ProvisionSandbox,
    RunCommand,
    AgentPrompt,
    Snapshot,
    DesktopStream,
    K8sPod,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Worker {
    pub id: WorkerId,
    pub tenant_id: String,
    pub name: String,
    pub status: WorkerStatus,
    pub provider: String,
    pub capabilities: Vec<WorkerCapability>,
    #[serde(default = "default_max_concurrent_jobs")]
    pub max_concurrent_jobs: u32,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
}

fn default_max_concurrent_jobs() -> u32 {
    1
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterWorkerRequest {
    pub name: String,
    pub provider: String,
    pub capabilities: Vec<WorkerCapability>,
    pub max_concurrent_jobs: Option<u32>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerHeartbeatRequest {
    pub max_concurrent_jobs: Option<u32>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub ok: bool,
    pub worker: Worker,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerListResponse {
    pub ok: bool,
    pub workers: Vec<Worker>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkerCapacity {
    pub worker_id: WorkerId,
    pub worker_name: String,
    pub provider: String,
    pub status: WorkerStatus,
    pub max_concurrent_jobs: u32,
    pub active_leases: u32,
    pub available_slots: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapacityResponse {
    pub ok: bool,
    pub workers: Vec<WorkerCapacity>,
    pub total_max_concurrent_jobs: u32,
    pub total_active_leases: u32,
    pub total_available_slots: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    ProvisionSandbox,
    StopSandbox,
    ResumeSandbox,
    RunCommand,
    RunPrompt,
    CreateSnapshot,
    ForkSandbox,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Leased,
    Succeeded,
    Failed,
    Dead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Active,
    Completed,
    Failed,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Job {
    pub id: JobId,
    pub tenant_id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub payload: serde_json::Value,
    pub required_capability: WorkerCapability,
    pub priority: i64,
    pub attempts: i64,
    pub max_attempts: i64,
    pub scheduled_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobLease {
    pub id: LeaseId,
    pub job_id: JobId,
    pub worker_id: WorkerId,
    pub status: LeaseStatus,
    pub attempt: i64,
    pub leased_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub job: Job,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateJobRequest {
    pub kind: JobKind,
    pub payload: serde_json::Value,
    pub required_capability: WorkerCapability,
    pub priority: Option<i64>,
    pub max_attempts: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimLeaseRequest {
    pub lease_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RenewLeaseRequest {
    pub lease_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompleteLeaseRequest {
    pub result: Option<WorkerJobResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FailLeaseRequest {
    pub error: String,
    pub retry: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobResponse {
    pub ok: bool,
    pub job: Job,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobListResponse {
    pub ok: bool,
    pub jobs: Vec<Job>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LeaseResponse {
    pub ok: bool,
    pub lease: JobLease,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimLeaseResponse {
    pub ok: bool,
    pub lease: Option<JobLease>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentCommandRequest {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentCommandResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentHealthResponse {
    pub ok: bool,
    pub agent: String,
    pub ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderHealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderCapabilityReport {
    pub provider: String,
    pub capabilities: Vec<WorkerCapability>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderHealthReport {
    pub provider: String,
    pub status: ProviderHealthStatus,
    pub checked_at: DateTime<Utc>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderSandboxHandle {
    pub provider: String,
    #[serde(alias = "sandboxId")]
    pub sandbox_id: SandboxId,
    #[serde(default)]
    pub resources: Vec<ProviderRuntimeResource>,
    #[serde(default, alias = "providerMetadata")]
    pub metadata: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderSnapshotHandle {
    pub provider: String,
    #[serde(alias = "snapshotId")]
    pub snapshot_id: SnapshotId,
    #[serde(default)]
    pub resources: Vec<ProviderRuntimeResource>,
    #[serde(default, alias = "providerMetadata")]
    pub metadata: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderForkHandle {
    pub provider: String,
    #[serde(alias = "parentSandboxId")]
    pub parent_sandbox_id: SandboxId,
    #[serde(alias = "childSandboxId")]
    pub child_sandbox_id: SandboxId,
    #[serde(alias = "snapshotId")]
    pub snapshot_id: SnapshotId,
    #[serde(default)]
    pub resources: Vec<ProviderRuntimeResource>,
    #[serde(default, alias = "providerMetadata")]
    pub metadata: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkerJobResult {
    ProvisionSandbox {
        handle: ProviderSandboxHandle,
    },
    RunCommand {
        result: AgentCommandResult,
    },
    RunPrompt {
        output: String,
    },
    CreateSnapshot {
        handle: ProviderSnapshotHandle,
    },
    ForkSandbox {
        handle: ProviderForkHandle,
    },
    StopSandbox {
        provider: String,
        sandbox_id: SandboxId,
    },
    ResumeSandbox {
        provider: String,
        sandbox_id: SandboxId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestStatus {
    Pending,
    Ready,
    Unreachable,
    Unhealthy,
    Terminated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuestHealth {
    pub sandbox_id: SandboxId,
    pub status: GuestStatus,
    pub last_probe_at: DateTime<Utc>,
    pub agent_version: Option<String>,
    pub checks: serde_json::Value,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateGuestHealthRequest {
    pub status: GuestStatus,
    pub agent_version: Option<String>,
    pub checks: Option<serde_json::Value>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuestHealthResponse {
    pub ok: bool,
    pub guest_health: GuestHealth,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshKeyStatus {
    Requested,
    Applied,
    Failed,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SshKey {
    pub id: SshKeyId,
    pub sandbox_id: SandboxId,
    pub public_key: String,
    pub principal: String,
    pub status: SshKeyStatus,
    pub requested_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub applied_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestSshKeyRequest {
    pub public_key: String,
    pub principal: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateSshKeyStatusRequest {
    pub status: SshKeyStatus,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SshKeyResponse {
    pub ok: bool,
    pub ssh_key: SshKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SshKeyListResponse {
    pub ok: bool,
    pub ssh_keys: Vec<SshKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthComponent {
    pub ok: bool,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub service: String,
    #[serde(default = "default_checked_at")]
    pub checked_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<HealthComponent>,
}

fn default_checked_at() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(0, 0).expect("unix epoch is valid")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub ok: bool,
    pub code: String,
    pub message: String,
}

impl ErrorEnvelope {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: code.into(),
            message: message.into(),
        }
    }
}
