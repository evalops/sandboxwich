use std::{collections::BTreeMap, fmt};

use base64::{Engine as _, engine::general_purpose};
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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("invalid {enum_name} variant {value:?}; expected one of {expected:?}")]
pub struct DbVariantError {
    pub enum_name: &'static str,
    pub value: String,
    pub expected: &'static [&'static str],
}

pub trait DbVariant: Sized {
    const VALUES: &'static [&'static str];

    fn as_db_str(&self) -> &'static str;
    fn parse_db_str(value: &str) -> Result<Self, DbVariantError>;
}

macro_rules! db_variant_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident => $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl DbVariant for $name {
            const VALUES: &'static [&'static str] = &[$($value),+];

            fn as_db_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }

            fn parse_db_str(value: &str) -> Result<Self, DbVariantError> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(DbVariantError {
                        enum_name: stringify!($name),
                        value: value.to_string(),
                        expected: Self::VALUES,
                    }),
                }
            }
        }
    };
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
pub struct FileId(pub Uuid);

impl FileId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for FileId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for FileId {
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

db_variant_enum! {
pub enum SandboxState {
    Planning => "planning",
    Provisioning => "provisioning",
    Ready => "ready",
    Running => "running",
    Idle => "idle",
    Archiving => "archiving",
    Archived => "archived",
    Error => "error",
}
}

db_variant_enum! {
pub enum SnapshotStatus {
    Pending => "pending",
    Ready => "ready",
    Failed => "failed",
    Expired => "expired",
}
}

db_variant_enum! {
pub enum DesktopSessionStatus {
    Pending => "pending",
    Ready => "ready",
    Failed => "failed",
    Closed => "closed",
    Expired => "expired",
}
}

db_variant_enum! {
pub enum DesktopAccessMode {
    Browser => "browser",
    Vnc => "vnc",
    Rdp => "rdp",
}
}

db_variant_enum! {
pub enum RuntimeResourceKind {
    Pod => "pod",
    PersistentVolumeClaim => "persistent_volume_claim",
    Service => "service",
    VolumeSnapshot => "volume_snapshot",
    NetworkPolicy => "network_policy",
}
}

db_variant_enum! {
pub enum RuntimeResourcePurpose {
    Runtime => "runtime",
    Workspace => "workspace",
    Ssh => "ssh",
    Desktop => "desktop",
    Snapshot => "snapshot",
    Network => "network",
}
}

db_variant_enum! {
pub enum RuntimeResourceStatus {
    Planned => "planned",
    Applied => "applied",
    Ready => "ready",
    Failed => "failed",
    Deleted => "deleted",
    Destroyed => "destroyed",
}
}

db_variant_enum! {
pub enum CleanupRunStatus {
    Running => "running",
    Succeeded => "succeeded",
    Failed => "failed",
}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryLimit {
    OneG,
    FourG,
    SixteenG,
    SixtyFourG,
}

impl Default for MemoryLimit {
    fn default() -> Self {
        Self::OneG
    }
}

impl MemoryLimit {
    pub fn cpu_limit(&self) -> &'static str {
        match self {
            Self::OneG => "500m",
            Self::FourG => "1",
            Self::SixteenG => "4",
            Self::SixtyFourG => "16",
        }
    }

    pub fn memory_quantity(&self) -> &'static str {
        match self {
            Self::OneG => "1Gi",
            Self::FourG => "4Gi",
            Self::SixteenG => "16Gi",
            Self::SixtyFourG => "64Gi",
        }
    }

    pub fn disk_limit(&self) -> &'static str {
        match self {
            Self::OneG => "2Gi",
            Self::FourG => "8Gi",
            Self::SixteenG => "32Gi",
            Self::SixtyFourG => "128Gi",
        }
    }
}

impl DbVariant for MemoryLimit {
    const VALUES: &'static [&'static str] = &["1g", "4g", "16g", "64g"];

    fn as_db_str(&self) -> &'static str {
        match self {
            Self::OneG => "1g",
            Self::FourG => "4g",
            Self::SixteenG => "16g",
            Self::SixtyFourG => "64g",
        }
    }

    fn parse_db_str(value: &str) -> Result<Self, DbVariantError> {
        match value {
            "1g" => Ok(Self::OneG),
            "4g" => Ok(Self::FourG),
            "16g" => Ok(Self::SixteenG),
            "64g" => Ok(Self::SixtyFourG),
            _ => Err(DbVariantError {
                enum_name: "MemoryLimit",
                value: value.to_string(),
                expected: Self::VALUES,
            }),
        }
    }
}

impl fmt::Display for MemoryLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_db_str())
    }
}

impl Serialize for MemoryLimit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_db_str())
    }
}

impl<'de> Deserialize<'de> for MemoryLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_db_str(&value).map_err(serde::de::Error::custom)
    }
}

db_variant_enum! {
pub enum NetworkEgressMode {
    DenyAll => "deny_all",
    Allowlist => "allowlist",
    AllowAll => "allow_all",
}
}

db_variant_enum! {
pub enum NetworkAllowRuleKind {
    Cidr => "cidr",
    Host => "host",
}
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkAllowRule {
    pub kind: NetworkAllowRuleKind,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkEgress {
    DenyAll,
    Allowlist { rules: Vec<NetworkAllowRule> },
    AllowAll,
}

impl Default for NetworkEgress {
    fn default() -> Self {
        Self::DenyAll
    }
}

impl NetworkEgress {
    pub fn mode(&self) -> NetworkEgressMode {
        match self {
            Self::DenyAll => NetworkEgressMode::DenyAll,
            Self::Allowlist { .. } => NetworkEgressMode::Allowlist,
            Self::AllowAll => NetworkEgressMode::AllowAll,
        }
    }

    pub fn rules(&self) -> &[NetworkAllowRule] {
        match self {
            Self::Allowlist { rules } => rules,
            Self::DenyAll | Self::AllowAll => &[],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxProvisionSpec {
    #[serde(default)]
    pub memory_limit: MemoryLimit,
    #[serde(default)]
    pub network_egress: NetworkEgress,
}

impl Default for SandboxProvisionSpec {
    fn default() -> Self {
        Self {
            memory_limit: MemoryLimit::default(),
            network_egress: NetworkEgress::default(),
        }
    }
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
    pub memory_limit: MemoryLimit,
    #[serde(default)]
    pub network_egress: NetworkEgress,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ttl_seconds: Option<u64>,
    pub parent_snapshot_id: Option<SnapshotId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateSandboxRequest {
    pub name: Option<String>,
    pub template: Option<String>,
    pub memory_limit: Option<MemoryLimit>,
    pub network_egress: Option<NetworkEgress>,
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
    /// Opaque keyset cursor for the next page, present only when more results exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeResourceListResponse {
    pub ok: bool,
    pub resources: Vec<RuntimeResource>,
}

/// Maximum size of a file that can be uploaded into a sandbox and stored (base64-encoded) in the
/// primary database. Kept well below the historical 512 MiB cap: base64 inflates storage by ~33%,
/// every stored byte lives in the primary DB (not object storage), and the whole file is buffered
/// in process memory both on upload and on download. 64 MiB covers the overwhelming majority of
/// legitimate config/source/small-artifact uploads while bounding per-request memory and DB bloat.
/// Workloads that need larger blobs should use snapshots or an external object store (tracked as
/// follow-up work, not implemented in this change).
pub const MAX_SANDBOX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UploadFileRequest {
    pub path: String,
    pub mime_type: Option<String>,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxFile {
    pub id: FileId,
    pub sandbox_id: SandboxId,
    pub path: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ListFilesResponse {
    pub ok: bool,
    pub files: Vec<SandboxFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileResponse {
    pub ok: bool,
    pub file: SandboxFile,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DownloadFileResponse {
    pub ok: bool,
    pub file: SandboxFile,
    pub content: Vec<u8>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
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

db_variant_enum! {
pub enum CommandStatus {
    Queued => "queued",
    Running => "running",
    Finished => "finished",
    Failed => "failed",
}
}

db_variant_enum! {
pub enum CommandOutputStream {
    Stdout => "stdout",
    Stderr => "stderr",
}
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
pub struct QueuedCommandJob {
    pub id: JobId,
    pub sandbox_id: SandboxId,
    pub command_id: CommandId,
    pub kind: JobKind,
    pub status: JobStatus,
    pub required_capability: WorkerCapability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueueCommandResponse {
    pub ok: bool,
    pub command: CommandRun,
    pub queued_job: QueuedCommandJob,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandListResponse {
    pub ok: bool,
    pub commands: Vec<CommandRun>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandOutputChunk {
    pub id: CommandOutputChunkId,
    pub command_id: CommandId,
    pub stream: CommandOutputStream,
    pub sequence: u64,
    pub chunk: String,
    #[serde(default)]
    pub annotations: Vec<CommandOutputAnnotation>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppendCommandOutputRequest {
    pub stream: CommandOutputStream,
    pub chunk: String,
    #[serde(default)]
    pub annotations: Vec<CommandOutputAnnotation>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommandOutputAnnotation {
    ContainerFileCitation {
        file_id: FileId,
        path: String,
        start_index: Option<u64>,
        end_index: Option<u64>,
    },
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

db_variant_enum! {
pub enum SandboxEventKind {
    LifecycleChanged => "lifecycle_changed",
    CommandQueued => "command_queued",
    CommandStarted => "command_started",
    CommandOutput => "command_output",
    CommandFinished => "command_finished",
    PromptQueued => "prompt_queued",
    PromptStarted => "prompt_started",
    PromptFinished => "prompt_finished",
    DesktopRequested => "desktop_requested",
    DesktopReady => "desktop_ready",
    DesktopFailed => "desktop_failed",
    DesktopClosed => "desktop_closed",
    DesktopExpired => "desktop_expired",
    FileUploaded => "file_uploaded",
}
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

db_variant_enum! {
pub enum WorkerStatus {
    Registered => "registered",
    Online => "online",
    Draining => "draining",
    Offline => "offline",
}
}

db_variant_enum! {
pub enum WorkerCapability {
    ProvisionSandbox => "provision_sandbox",
    RunCommand => "run_command",
    AgentPrompt => "agent_prompt",
    Snapshot => "snapshot",
    DesktopStream => "desktop_stream",
    K8sPod => "k8s_pod",
    GvisorSandbox => "gvisor_sandbox",
}
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

db_variant_enum! {
pub enum JobKind {
    ProvisionSandbox => "provision_sandbox",
    StopSandbox => "stop_sandbox",
    ResumeSandbox => "resume_sandbox",
    RunCommand => "run_command",
    RunPrompt => "run_prompt",
    CreateSnapshot => "create_snapshot",
    ForkSandbox => "fork_sandbox",
}
}

db_variant_enum! {
pub enum JobStatus {
    Queued => "queued",
    Leased => "leased",
    Succeeded => "succeeded",
    Failed => "failed",
    Dead => "dead",
}
}

db_variant_enum! {
pub enum LeaseStatus {
    Active => "active",
    Completed => "completed",
    Failed => "failed",
    Expired => "expired",
}
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
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
pub struct AgentFileWriteRequest {
    pub path: String,
    #[serde(with = "serde_base64_bytes")]
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentFileReadRequest {
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentFileReadResponse {
    pub path: String,
    #[serde(with = "serde_base64_bytes")]
    pub content: Vec<u8>,
}

mod serde_base64_bytes {
    use super::*;

    pub fn serialize<S>(content: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(content))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

db_variant_enum! {
pub enum ProviderHealthStatus {
    Healthy => "healthy",
    Degraded => "degraded",
    Unhealthy => "unhealthy",
}
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

db_variant_enum! {
pub enum GuestStatus {
    Pending => "pending",
    Ready => "ready",
    Unreachable => "unreachable",
    Unhealthy => "unhealthy",
    Terminated => "terminated",
}
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

db_variant_enum! {
pub enum SshKeyStatus {
    Requested => "requested",
    Applied => "applied",
    Failed => "failed",
    Revoked => "revoked",
}
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, de::DeserializeOwned};
    use std::{collections::BTreeSet, fmt::Debug};

    fn assert_db_variant_contract<T>()
    where
        T: DbVariant + Serialize + DeserializeOwned + Debug + PartialEq,
    {
        let mut seen = BTreeSet::new();
        for value in T::VALUES {
            assert!(seen.insert(*value), "duplicate db variant value {value}");
            let parsed = T::parse_db_str(value).expect("declared value must parse");
            assert_eq!(parsed.as_db_str(), *value);
            let json = serde_json::to_string(&parsed).expect("variant should serialize");
            assert_eq!(json, format!("\"{value}\""));
            let decoded: T = serde_json::from_str(&json).expect("variant should deserialize");
            assert_eq!(decoded, parsed);
        }
        assert!(T::parse_db_str("__not_a_variant__").is_err());
    }

    #[test]
    fn db_variants_round_trip_through_declared_values_and_json() {
        assert_db_variant_contract::<SandboxState>();
        assert_db_variant_contract::<SnapshotStatus>();
        assert_db_variant_contract::<DesktopSessionStatus>();
        assert_db_variant_contract::<DesktopAccessMode>();
        assert_db_variant_contract::<RuntimeResourceKind>();
        assert_db_variant_contract::<RuntimeResourcePurpose>();
        assert_db_variant_contract::<RuntimeResourceStatus>();
        assert_db_variant_contract::<CleanupRunStatus>();
        assert_db_variant_contract::<MemoryLimit>();
        assert_db_variant_contract::<NetworkEgressMode>();
        assert_db_variant_contract::<NetworkAllowRuleKind>();
        assert_db_variant_contract::<CommandStatus>();
        assert_db_variant_contract::<CommandOutputStream>();
        assert_db_variant_contract::<SandboxEventKind>();
        assert_db_variant_contract::<WorkerStatus>();
        assert_db_variant_contract::<WorkerCapability>();
        assert_db_variant_contract::<JobKind>();
        assert_db_variant_contract::<JobStatus>();
        assert_db_variant_contract::<LeaseStatus>();
        assert_db_variant_contract::<ProviderHealthStatus>();
        assert_db_variant_contract::<GuestStatus>();
        assert_db_variant_contract::<SshKeyStatus>();
    }

    #[test]
    fn agent_file_payloads_serialize_content_as_base64() {
        let payload = AgentFileReadResponse {
            path: "/workspace/out.bin".to_string(),
            content: b"hello\0world".to_vec(),
        };

        let json = serde_json::to_value(&payload).expect("file payload should serialize");
        assert_eq!(json["content"], "aGVsbG8Ad29ybGQ=");

        let decoded: AgentFileReadResponse =
            serde_json::from_value(json).expect("file payload should deserialize");
        assert_eq!(decoded, payload);
    }
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
