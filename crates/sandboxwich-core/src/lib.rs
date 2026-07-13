use std::{collections::BTreeMap, fmt, time::Duration};

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

/// Default timeout for establishing the TCP/TLS connection to the control
/// plane. Overridable with [`CONNECT_TIMEOUT_ENV_VAR`]; a value of `0`
/// disables it.
pub const DEFAULT_API_CLIENT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default end-to-end timeout for a single control-plane request. Mirrors
/// `sandboxwich-cli`'s `--request-timeout-secs` default (30s) and shares its
/// env var so operators only need to remember one knob. Overridable with
/// [`REQUEST_TIMEOUT_ENV_VAR`]; a value of `0` disables it.
pub const DEFAULT_API_CLIENT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Env var overriding the default total request timeout applied by
/// [`build_api_client`]. A value of `0` disables the timeout entirely.
pub const REQUEST_TIMEOUT_ENV_VAR: &str = "SANDBOXWICH_REQUEST_TIMEOUT_SECS";

/// Env var overriding the default connect timeout applied by
/// [`build_api_client`]. A value of `0` disables the timeout entirely.
pub const CONNECT_TIMEOUT_ENV_VAR: &str = "SANDBOXWICH_CONNECT_TIMEOUT_SECS";

/// Builds the shared control-plane HTTP client used by every worker and
/// agent process. Applies sensible default connect/request timeouts (see
/// [`DEFAULT_API_CLIENT_CONNECT_TIMEOUT_SECS`] /
/// [`DEFAULT_API_CLIENT_REQUEST_TIMEOUT_SECS`], overridable via
/// [`CONNECT_TIMEOUT_ENV_VAR`] / [`REQUEST_TIMEOUT_ENV_VAR`]) so a
/// partitioned network or an API that accepts a connection but never
/// responds can't wedge the caller forever. Before these were added, every
/// worker/agent call through this client could hang indefinitely, and
/// `sandboxwich-agent`'s `AgentRequestError::is_recoverable` (which checks
/// `reqwest::Error::is_timeout`) could never observe a timeout to recover
/// from.
///
/// Use [`build_api_client_with_timeouts`] to set explicit timeouts instead of
/// reading them from the environment (e.g. in tests, or for a call site that
/// legitimately needs a longer bound).
pub fn build_api_client(
    api_token: Option<&str>,
    tenant: Option<&str>,
) -> Result<reqwest::Client, ApiClientBuildError> {
    build_api_client_with_timeouts(
        api_token,
        tenant,
        timeout_from_env(
            REQUEST_TIMEOUT_ENV_VAR,
            DEFAULT_API_CLIENT_REQUEST_TIMEOUT_SECS,
        ),
        timeout_from_env(
            CONNECT_TIMEOUT_ENV_VAR,
            DEFAULT_API_CLIENT_CONNECT_TIMEOUT_SECS,
        ),
    )
}

/// Like [`build_api_client`], but with explicit timeouts instead of reading
/// them from the environment. `None` disables the corresponding timeout.
pub fn build_api_client_with_timeouts(
    api_token: Option<&str>,
    tenant: Option<&str>,
    request_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
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
    let mut builder = reqwest::Client::builder().default_headers(headers);
    if let Some(connect_timeout) = connect_timeout {
        builder = builder.connect_timeout(connect_timeout);
    }
    if let Some(request_timeout) = request_timeout {
        builder = builder.timeout(request_timeout);
    }
    builder.build().map_err(ApiClientBuildError::Build)
}

/// Reads a timeout override from `var`: `0` disables the timeout, a missing
/// or unparsable value falls back to `default_secs`, anything else is used
/// verbatim as a second count.
fn timeout_from_env(var: &str, default_secs: u64) -> Option<Duration> {
    parse_timeout_override(std::env::var(var).ok().as_deref(), default_secs)
}

/// Pure parsing logic behind [`timeout_from_env`], split out so it can be
/// exercised by tests without mutating real process environment variables
/// (which would race with other tests running in the same binary).
fn parse_timeout_override(raw: Option<&str>, default_secs: u64) -> Option<Duration> {
    match raw {
        Some(value) => match value.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(secs) => Some(Duration::from_secs(secs)),
            Err(_) => Some(Duration::from_secs(default_secs)),
        },
        None => Some(Duration::from_secs(default_secs)),
    }
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
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
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
pub enum WorkspaceMode {
    Ephemeral => "ephemeral",
    GenericEphemeral => "generic_ephemeral",
    Persistent => "persistent",
}
}

// The shared database-enum macro owns the derive list and does not expose a
// per-variant `#[default]` hook, so this default must remain explicit.
#[allow(clippy::derivable_impls)]
impl Default for WorkspaceMode {
    fn default() -> Self {
        Self::Persistent
    }
}

impl SandboxState {
    /// Every declared sandbox lifecycle state.
    pub const ALL: [SandboxState; 8] = [
        SandboxState::Planning,
        SandboxState::Provisioning,
        SandboxState::Ready,
        SandboxState::Running,
        SandboxState::Idle,
        SandboxState::Archiving,
        SandboxState::Archived,
        SandboxState::Error,
    ];

    /// States from which a user-initiated `POST /sandboxes/{id}/stop` may
    /// legally move a sandbox to `Archived`. A sandbox that is already
    /// `Archived` is deliberately excluded: a double-stop surfaces as a 409
    /// conflict rather than a silent no-op, so a caller notices it raced
    /// someone (or something) else.
    pub const STOP_LEGAL_FROM: &'static [SandboxState] = &[
        SandboxState::Planning,
        SandboxState::Provisioning,
        SandboxState::Ready,
        SandboxState::Running,
        SandboxState::Idle,
        SandboxState::Error,
    ];

    /// A provider-confirmed teardown completes an archival already in progress.
    pub const STOP_COMPLETED_LEGAL_FROM: &'static [SandboxState] = &[SandboxState::Archiving];

    /// A sandbox can only be resumed from `Archived`. Resuming from any other
    /// state (in particular `Error`) would either race a job that is still
    /// writing to the sandbox, or paper over a failure that a fresh
    /// fork/create should handle instead.
    /// A `ForkSandbox` job being claimed by a worker moves its child sandbox
    /// out of `Planning` (queued, waiting on the parent snapshot) into
    /// `Provisioning`.
    pub const FORK_CLAIMED_LEGAL_FROM: &'static [SandboxState] = &[SandboxState::Planning];

    /// A `ForkSandbox` job completing successfully moves its child sandbox
    /// from `Provisioning` to `Ready`.
    pub const FORK_COMPLETED_LEGAL_FROM: &'static [SandboxState] = &[SandboxState::Provisioning];

    /// A `ForkSandbox` job that failed but is being retried moves its child
    /// sandbox back from `Provisioning` to `Planning`.
    pub const FORK_RETRIED_LEGAL_FROM: &'static [SandboxState] = &[SandboxState::Provisioning];

    /// A `ForkSandbox` job that failed permanently moves its child sandbox
    /// from `Provisioning` to `Error`.
    pub const FORK_FAILED_LEGAL_FROM: &'static [SandboxState] = &[SandboxState::Provisioning];

    /// A `ProvisionSandbox` job completing successfully moves a sandbox to
    /// `Ready`. Unlike `ForkSandbox`, this job kind can be queued directly
    /// against a sandbox in effectively any state via `POST /jobs` (e.g. to
    /// reprovision an already-`Ready` sandbox's runtime resources), so its
    /// legal predecessor set is deliberately broad. `Archived` is the one
    /// state excluded: a sandbox that was stopped while a provision job was
    /// in flight must stay archived, not get resurrected by that job's
    /// completion landing afterwards.
    pub const PROVISION_COMPLETED_LEGAL_FROM: &'static [SandboxState] = &[
        SandboxState::Planning,
        SandboxState::Provisioning,
        SandboxState::Ready,
        SandboxState::Running,
        SandboxState::Idle,
        SandboxState::Error,
    ];

    /// A child sandbox still `Planning` (queued, waiting on its parent's
    /// snapshot) moves to `Error` when that parent's `CreateSnapshot` job
    /// fails.
    pub const SNAPSHOT_FAILED_CHILD_LEGAL_FROM: &'static [SandboxState] = &[SandboxState::Planning];

    /// The sandbox lifecycle state machine: is `self -> next` a transition
    /// exercised by *some* legitimate caller?
    ///
    /// | From         | To           | Trigger                                              |
    /// |--------------|--------------|-------------------------------------------------------|
    /// | Planning     | Provisioning | `ForkSandbox` job claimed                              |
    /// | Planning     | Ready        | `ProvisionSandbox` job completed                       |
    /// | Planning     | Error        | parent `CreateSnapshot` job failed                     |
    /// | Planning     | Archiving    | user stop requested                                    |
    /// | Provisioning | Ready        | `ForkSandbox`/`ProvisionSandbox` job completed          |
    /// | Provisioning | Planning     | `ForkSandbox` job retried                              |
    /// | Provisioning | Error        | `ForkSandbox` job permanently failed                    |
    /// | Provisioning | Archiving    | user stop requested                                    |
    /// | Ready        | Ready        | `ProvisionSandbox` job completed (reprovision, no-op)   |
    /// | Ready        | Archiving    | user stop requested                                    |
    /// | Running      | Ready        | `ProvisionSandbox` job completed                       |
    /// | Running      | Archiving    | user stop requested                                    |
    /// | Idle         | Ready        | `ProvisionSandbox` job completed                       |
    /// | Idle         | Archiving    | user stop requested                                    |
    /// | Archiving    | Archived     | provider-confirmed stop completion                     |
    /// | Error        | Ready        | `ProvisionSandbox` job completed (manual retry)         |
    /// | Error        | Archiving    | user stop requested                                    |
    ///
    /// This is a coarse union of every `_LEGAL_FROM` constant above and is
    /// used as a database-level backstop trigger (see
    /// `sandbox_legal_transition_pairs`, `sqlite_sandbox_transition_guard_statements`,
    /// and `postgres_sandbox_transition_guard_statements` in sandboxwich-api)
    /// and in tests. It is deliberately *not* used to enforce any single action's precise
    /// preconditions — e.g. resume is legal only from `Archived` even though
    /// `Planning -> Ready` is legal in the broader provision-complete sense.
    /// Application code must use the specific `_LEGAL_FROM` constant for the
    /// action it is performing.
    pub fn can_transition_to(&self, next: &SandboxState) -> bool {
        (Self::STOP_LEGAL_FROM.contains(self) && *next == SandboxState::Archiving)
            || (Self::STOP_COMPLETED_LEGAL_FROM.contains(self) && *next == SandboxState::Archived)
            || (Self::FORK_CLAIMED_LEGAL_FROM.contains(self) && *next == SandboxState::Provisioning)
            || (Self::FORK_COMPLETED_LEGAL_FROM.contains(self) && *next == SandboxState::Ready)
            || (Self::FORK_RETRIED_LEGAL_FROM.contains(self) && *next == SandboxState::Planning)
            || (Self::FORK_FAILED_LEGAL_FROM.contains(self) && *next == SandboxState::Error)
            || (Self::PROVISION_COMPLETED_LEGAL_FROM.contains(self) && *next == SandboxState::Ready)
            || (Self::SNAPSHOT_FAILED_CHILD_LEGAL_FROM.contains(self)
                && *next == SandboxState::Error)
    }

    /// Every state that can legally transition into `next` per
    /// [`can_transition_to`](Self::can_transition_to). Used to build the
    /// database backstop trigger's `(old_state, new_state) IN (...)`
    /// predicate.
    pub fn legal_predecessors(next: &SandboxState) -> Vec<SandboxState> {
        Self::ALL
            .iter()
            .filter(|from| from.can_transition_to(next))
            .cloned()
            .collect()
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
    Secret => "secret",
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

#[derive(Clone, Debug, Eq, PartialEq, Default, utoipa::ToSchema)]
pub enum MemoryLimit {
    #[default]
    OneG,
    FourG,
    SixteenG,
    SixtyFourG,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NetworkAllowRule {
    pub kind: NetworkAllowRuleKind,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkEgress {
    #[default]
    DenyAll,
    Allowlist {
        rules: Vec<NetworkAllowRule>,
    },
    AllowAll,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SandboxProvisionSpec {
    #[serde(default)]
    pub memory_limit: MemoryLimit,
    #[serde(default)]
    pub network_egress: NetworkEgress,
    #[serde(default)]
    pub workspace_mode: WorkspaceMode,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Sandbox {
    pub id: SandboxId,
    pub tenant_id: String,
    pub name: String,
    pub state: SandboxState,
    pub template: String,
    pub memory_limit: MemoryLimit,
    #[serde(default)]
    pub network_egress: NetworkEgress,
    #[serde(default)]
    pub workspace_mode: WorkspaceMode,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ttl_seconds: Option<u64>,
    pub parent_snapshot_id: Option<SnapshotId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateSandboxRequest {
    pub name: Option<String>,
    pub template: Option<String>,
    pub memory_limit: Option<MemoryLimit>,
    pub network_egress: Option<NetworkEgress>,
    pub workspace_mode: Option<WorkspaceMode>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SandboxResponse {
    pub ok: bool,
    pub sandbox: Sandbox,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,
}

/// Provider-facing projection used by external control planes to reconcile a
/// sandbox without depending on the full tenant-visible Sandbox resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SandboxObservedState {
    pub sandbox_id: Uuid,
    pub tenant_id: String,
    pub state: SandboxState,
    pub observed_at: DateTime<Utc>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeResourceInventoryItem {
    pub sandbox_id: SandboxId,
    pub resource_kind: RuntimeResourceKind,
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub cleanup_deadline: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeResourceInventoryResponse {
    pub ok: bool,
    pub provider: String,
    pub cluster: Option<String>,
    pub namespace: String,
    pub sandbox_ids: Vec<SandboxId>,
    pub complete: bool,
    pub resources: Vec<RuntimeResourceInventoryItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
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

db_variant_enum! {
pub enum ActivityClass {
    ProcessSpawn => "process_spawn",
    NetworkConnect => "network_connect",
    FileWrite => "file_write",
}
}

db_variant_enum! {
pub enum DivergenceKind {
    UnaccountedActivity => "unaccounted_activity",
    ReceiptScopeMismatch => "receipt_scope_mismatch",
}
}

db_variant_enum! {
pub enum DivergenceFindingStatus {
    Open => "open",
    Resolved => "resolved",
}
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReceiptScope {
    pub activity_class: ActivityClass,
    pub resource_prefix: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ToolCallLedgerEntryRequest {
    pub external_id: String,
    pub session_id: String,
    pub receipt_id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub scopes: Vec<ReceiptScope>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SensorObservation {
    pub external_id: String,
    pub sandbox_id: SandboxId,
    pub session_id: String,
    pub activity_class: ActivityClass,
    pub resource: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DivergenceFinding {
    pub id: Uuid,
    pub sandbox_id: SandboxId,
    pub observation_external_id: String,
    pub session_id: String,
    pub receipt_id: Option<String>,
    pub kind: DivergenceKind,
    pub activity_class: ActivityClass,
    pub resource: String,
    pub status: DivergenceFindingStatus,
    pub detected_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DivergenceReconcileResponse {
    pub ok: bool,
    pub observations_ingested: u64,
    pub observations_matched: u64,
    pub findings_created: Vec<DivergenceFinding>,
    pub retry_after: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DivergenceReconcileRequest {
    pub source: String,
    pub observations: Vec<SensorObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DivergenceFindingListResponse {
    pub ok: bool,
    pub findings: Vec<DivergenceFinding>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateSnapshotRequest {
    pub label: Option<String>,
    pub inventory: Option<serde_json::Value>,
    pub provider_metadata: Option<serde_json::Value>,
    pub ttl_seconds: Option<u64>,
}

/// Complete child configuration for restoring directly from a durable
/// snapshot. Fields needed to provision the child are intentionally required
/// so this request does not depend on the source sandbox still existing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ForkSnapshotRequest {
    pub name: Option<String>,
    pub template: String,
    pub memory_limit: MemoryLimit,
    #[serde(default)]
    pub network_egress: NetworkEgress,
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SnapshotResponse {
    pub ok: bool,
    pub snapshot: Snapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<Operation>,
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

/// Default per-command execution timeout `queue_command` fills in when a
/// client omits `timeout_secs`, and `sandboxwich-agent`'s `execute_streaming`
/// falls back to when a `RunCommand` job's payload has no `timeoutSecs`
/// (e.g. the standalone `exec` CLI path, which never goes through
/// `queue_command`). Exists so `child.wait()` always has a bound instead of
/// being able to hang forever on a wedged command.
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 300;

/// Upper bound `queue_command` clamps a client-requested `timeout_secs`
/// against, so a command execution can't be configured as effectively
/// unbounded.
pub const MAX_COMMAND_TIMEOUT_SECS: u64 = 3600;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CommandRequest {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Maximum time the command may run before the executor kills it and
    /// reports a timeout failure. Clamped to
    /// `(0, MAX_COMMAND_TIMEOUT_SECS]` by `queue_command`; `None`/omitted
    /// falls back to `DEFAULT_COMMAND_TIMEOUT_SECS`.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CommandResponse {
    pub ok: bool,
    pub command: CommandRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueuedCommandJob {
    pub id: JobId,
    pub sandbox_id: SandboxId,
    pub command_id: CommandId,
    pub kind: JobKind,
    pub status: JobStatus,
    pub required_capability: WorkerCapability,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueueCommandResponse {
    pub ok: bool,
    pub command: CommandRun,
    pub queued_job: QueuedCommandJob,
    pub operation: Operation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandListResponse {
    pub ok: bool,
    pub commands: Vec<CommandRun>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CommandOutputListResponse {
    pub ok: bool,
    /// False while the command may still append more chunks.
    #[serde(default)]
    pub complete: bool,
    pub chunks: Vec<CommandOutputChunk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
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
    GuestHealthFailed => "guest_health_failed",
    FileUploaded => "file_uploaded",
    DivergenceDetected => "divergence_detected",
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
    FqdnEgress => "fqdn_egress",
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
    /// Present only in the response to `POST /workers/register`: a
    /// worker-scoped credential distinct from tenant tokens, bound to this
    /// worker's id (see GH-64). The worker must store it and use it (instead
    /// of its tenant token) for the guest-facing routes it and the sandboxes
    /// it provisions call: lease claim/renew/complete/fail/output and
    /// guest-health. It is never returned again after registration, so a
    /// worker that loses it must re-register to obtain a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MintGuestTokenRequest {
    pub ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuestTokenResponse {
    pub ok: bool,
    pub token: String,
    pub tenant_id: String,
    pub worker_id: WorkerId,
    pub sandbox_id: SandboxId,
    pub expires_at: DateTime<Utc>,
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
    Cancelled => "cancelled",
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

db_variant_enum! {
pub enum ProvisioningStage {
    WorkspacePlanned => "workspace_planned",
    WorkspaceReady => "workspace_ready",
    NetworkPolicyReady => "network_policy_ready",
    CredentialsReady => "credentials_ready",
    PodReady => "pod_ready",
    ServiceReady => "service_ready",
    SandboxReady => "sandbox_ready",
}
}

impl ProvisioningStage {
    pub fn ordinal(&self) -> u8 {
        match self {
            Self::WorkspacePlanned => 0,
            Self::WorkspaceReady => 1,
            Self::NetworkPolicyReady => 2,
            Self::CredentialsReady => 3,
            Self::PodReady => 4,
            Self::ServiceReady => 5,
            Self::SandboxReady => 6,
        }
    }
}

db_variant_enum! {
pub enum ProvisioningErrorClass {
    RetryableProvider => "retryable_provider",
    RetryableCapacity => "retryable_capacity",
    TerminalContract => "terminal_contract",
    TerminalSecurity => "terminal_security",
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
    /// Restrict claimable jobs to the given sandbox (matched against the job's own
    /// sandbox, or its fork parent/child sandbox). `None` preserves the previous
    /// behavior of claiming any job the worker's capabilities allow.
    ///
    /// This is advisory, not a security boundary: the guest agent and the worker
    /// it runs under share one worker-scoped token (see `sandboxwich-agent`'s
    /// `--sandbox-id`), so a malicious or compromised guest can simply omit this
    /// filter and claim any job the shared token's capabilities allow. The
    /// server-side filtering below narrows the *default* blast radius of a
    /// well-behaved agent claiming the wrong job; it does not stop an
    /// adversarial one. A real fix needs per-sandbox claim tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<SandboxId>,
    /// Restrict claimable jobs to one of the given kinds. `None` preserves the
    /// previous behavior of claiming any kind the worker's capabilities allow.
    /// Same advisory caveat as `sandbox_id` above applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<JobKind>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RenewLeaseRequest {
    pub lease_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProvisioningStageUpdateRequest {
    pub stage: ProvisioningStage,
    pub resource_kind: Option<RuntimeResourceKind>,
    pub resource_namespace: Option<String>,
    pub resource_name: Option<String>,
    pub resource_uid: Option<String>,
    pub observed_generation: Option<i64>,
    pub attempt_count: i64,
    pub last_error_class: Option<ProvisioningErrorClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProvisioningOperation {
    pub sandbox_id: SandboxId,
    pub lease_id: LeaseId,
    pub lease_attempt: i64,
    pub stage: ProvisioningStage,
    pub resource_kind: Option<RuntimeResourceKind>,
    pub resource_namespace: Option<String>,
    pub resource_name: Option<String>,
    pub resource_uid: Option<String>,
    pub observed_generation: Option<i64>,
    pub attempt_count: i64,
    pub last_error_class: Option<ProvisioningErrorClass>,
    pub last_error_code: Option<String>,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProvisioningOperationResponse {
    pub ok: bool,
    pub operation: ProvisioningOperation,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    ProvisionSandbox,
    StopSandbox,
    ResumeSandbox,
    RunCommand,
    CreateSnapshot,
    ForkSandbox,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Operation {
    pub id: Uuid,
    pub kind: OperationKind,
    pub status: OperationStatus,
    pub resource_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OperationResponse {
    pub ok: bool,
    pub operation: Operation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentCommandRequest {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Bound applied by `execute_streaming` around `child.wait()`; the child
    /// is killed and a distinct timeout failure reported if it runs longer
    /// than this. `None` falls back to `DEFAULT_COMMAND_TIMEOUT_SECS`.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
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
    fn provisioning_contract_variants_round_trip_through_db_and_json() {
        assert_eq!(RuntimeResourceKind::Secret.as_db_str(), "secret");
        for (stage, value) in [
            (ProvisioningStage::WorkspacePlanned, "workspace_planned"),
            (ProvisioningStage::WorkspaceReady, "workspace_ready"),
            (
                ProvisioningStage::NetworkPolicyReady,
                "network_policy_ready",
            ),
            (ProvisioningStage::CredentialsReady, "credentials_ready"),
            (ProvisioningStage::PodReady, "pod_ready"),
            (ProvisioningStage::ServiceReady, "service_ready"),
            (ProvisioningStage::SandboxReady, "sandbox_ready"),
        ] {
            assert_eq!(stage.as_db_str(), value);
            assert_eq!(ProvisioningStage::parse_db_str(value).unwrap(), stage);
            assert_eq!(serde_json::to_value(&stage).unwrap(), value);
        }

        for (class, value) in [
            (
                ProvisioningErrorClass::RetryableProvider,
                "retryable_provider",
            ),
            (
                ProvisioningErrorClass::RetryableCapacity,
                "retryable_capacity",
            ),
            (
                ProvisioningErrorClass::TerminalContract,
                "terminal_contract",
            ),
            (
                ProvisioningErrorClass::TerminalSecurity,
                "terminal_security",
            ),
        ] {
            assert_eq!(class.as_db_str(), value);
            assert_eq!(ProvisioningErrorClass::parse_db_str(value).unwrap(), class);
            assert_eq!(serde_json::to_value(&class).unwrap(), value);
        }
    }

    #[test]
    fn timeout_override_defaults_disables_and_parses() {
        // Unset (or unparsable) env var falls back to the caller's default.
        assert_eq!(
            parse_timeout_override(None, 30),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parse_timeout_override(Some("not-a-number"), 30),
            Some(Duration::from_secs(30))
        );
        // "0" is the documented opt-out for disabling the timeout entirely.
        assert_eq!(parse_timeout_override(Some("0"), 30), None);
        // Any other value is used verbatim.
        assert_eq!(
            parse_timeout_override(Some("5"), 30),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn build_api_client_with_timeouts_builds_successfully_with_and_without_timeouts() {
        // Every worker/agent call goes through this client; regression-test
        // that supplying explicit timeouts (the fix for the "hangs forever"
        // bug) still produces a valid client, and that `None`/`None`
        // (timeouts disabled) also still builds.
        build_api_client_with_timeouts(
            Some("token"),
            Some("tenant"),
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(10)),
        )
        .expect("client with explicit timeouts should build");

        build_api_client_with_timeouts(None, None, None, None)
            .expect("client with timeouts disabled should still build");
    }

    #[test]
    fn command_output_list_defaults_complete_for_older_servers() {
        let response: CommandOutputListResponse = serde_json::from_value(serde_json::json!({
            "ok": true,
            "chunks": []
        }))
        .expect("older response should remain readable");
        assert!(!response.complete);
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

    #[test]
    fn sandbox_state_legal_edges_match_the_documented_table() {
        use SandboxState::*;

        let legal_edges = [
            (Planning, Provisioning),
            (Planning, Ready),
            (Planning, Error),
            (Planning, Archiving),
            (Provisioning, Ready),
            (Provisioning, Planning),
            (Provisioning, Error),
            (Provisioning, Archiving),
            (Ready, Ready),
            (Ready, Archiving),
            (Running, Ready),
            (Running, Archiving),
            (Idle, Ready),
            (Idle, Archiving),
            (Archiving, Archived),
            (Error, Ready),
            (Error, Archiving),
        ];

        for from in SandboxState::ALL {
            for to in SandboxState::ALL {
                let expected = legal_edges.iter().any(|(f, t)| *f == from && *t == to);
                assert_eq!(
                    from.can_transition_to(&to),
                    expected,
                    "can_transition_to({from:?}, {to:?}) should be {expected}"
                );
            }
        }
    }

    #[test]
    fn archived_has_no_legal_resume_edge() {
        assert!(!SandboxState::Archived.can_transition_to(&SandboxState::Ready));
        assert_eq!(
            SandboxState::legal_predecessors(&SandboxState::Ready),
            vec![
                SandboxState::Planning,
                SandboxState::Provisioning,
                SandboxState::Ready,
                SandboxState::Running,
                SandboxState::Idle,
                SandboxState::Error,
            ],
            "archived sandboxes cannot become ready until a real restore contract exists"
        );
    }

    #[test]
    fn stop_excludes_archiving_and_archived() {
        for from in SandboxState::ALL {
            let expected = !matches!(from, SandboxState::Archiving | SandboxState::Archived);
            assert_eq!(
                SandboxState::STOP_LEGAL_FROM.contains(&from),
                expected,
                "stop legality for {from:?} should be {expected}"
            );
        }
    }

    #[test]
    fn provision_completed_excludes_archiving_and_archived() {
        for from in SandboxState::ALL {
            let expected = !matches!(from, SandboxState::Archiving | SandboxState::Archived);
            assert_eq!(
                SandboxState::PROVISION_COMPLETED_LEGAL_FROM.contains(&from),
                expected,
                "a stopping or archived sandbox must never be resurrected by a \
                 completing ProvisionSandbox job: {from:?} should be {expected}"
            );
        }
    }

    #[test]
    fn fork_lifecycle_only_moves_through_planning_and_provisioning() {
        assert_eq!(
            SandboxState::FORK_CLAIMED_LEGAL_FROM,
            [SandboxState::Planning].as_slice()
        );
        assert_eq!(
            SandboxState::FORK_COMPLETED_LEGAL_FROM,
            [SandboxState::Provisioning].as_slice()
        );
        assert_eq!(
            SandboxState::FORK_RETRIED_LEGAL_FROM,
            [SandboxState::Provisioning].as_slice()
        );
        assert_eq!(
            SandboxState::FORK_FAILED_LEGAL_FROM,
            [SandboxState::Provisioning].as_slice()
        );
        assert_eq!(
            SandboxState::SNAPSHOT_FAILED_CHILD_LEGAL_FROM,
            [SandboxState::Planning].as_slice()
        );
    }

    #[test]
    fn no_state_can_transition_to_itself_except_ready_reprovision() {
        for state in SandboxState::ALL {
            let self_loop = state.can_transition_to(&state);
            if state == SandboxState::Ready {
                assert!(
                    self_loop,
                    "Ready -> Ready is legal: reprovisioning an already-ready sandbox"
                );
            } else {
                assert!(!self_loop, "{state:?} -> {state:?} should not be legal");
            }
        }
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
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
