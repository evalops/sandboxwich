use crate::error::*;
use crate::handlers::files::*;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use sandboxwich_core::*;
use serde_json::json;
use sqlx::Row;
use sqlx::any::AnyRow;
use uuid::Uuid;

pub(crate) fn row_to_sandbox(row: AnyRow) -> Result<Sandbox, ApiError> {
    let id: String = row.try_get("id")?;
    let state: String = row.try_get("state")?;
    let memory_limit: String = row.try_get("memory_limit")?;
    let network_egress_mode: String = row.try_get("network_egress_mode")?;
    let workspace_mode: String = row.try_get("workspace_mode")?;
    let execution_class: String = row.try_get("execution_class")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let ttl_seconds: Option<i64> = row.try_get("ttl_seconds")?;
    let parent_snapshot_id: Option<String> = row.try_get("parent_snapshot_id")?;
    let network_egress = match parse_network_egress_mode(&network_egress_mode)? {
        NetworkEgressMode::DenyAll => NetworkEgress::DenyAll,
        NetworkEgressMode::Allowlist => NetworkEgress::Allowlist { rules: Vec::new() },
        NetworkEgressMode::AllowAll => NetworkEgress::AllowAll,
    };

    Ok(Sandbox {
        execution_class: ExecutionClass::parse_db_str(&execution_class)
            .map_err(|_| ApiError::internal("database contains invalid execution class"))?,
        id: SandboxId(parse_uuid(&id)?),
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        state: parse_state(&state)?,
        template: row.try_get("template")?,
        memory_limit: parse_memory_limit(&memory_limit)?,
        network_egress,
        workspace_mode: WorkspaceMode::parse_db_str(&workspace_mode)
            .map_err(|_| ApiError::internal("database contains invalid workspace mode"))?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        ttl_seconds: ttl_seconds.map(|ttl| ttl as u64),
        parent_snapshot_id: parent_snapshot_id
            .map(|snapshot| parse_uuid(&snapshot).map(SnapshotId))
            .transpose()?,
    })
}

pub(crate) fn row_to_network_allow_rule(row: AnyRow) -> Result<NetworkAllowRule, ApiError> {
    let kind: String = row.try_get("kind")?;
    Ok(NetworkAllowRule {
        kind: parse_network_allow_rule_kind(&kind)?,
        value: row.try_get("value")?,
    })
}

pub(crate) fn row_to_sandbox_file(row: AnyRow) -> Result<SandboxFile, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let size_bytes: i64 = row.try_get("size_bytes")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    Ok(SandboxFile {
        id: FileId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        path: row.try_get("path")?,
        size_bytes: u64::try_from(size_bytes)
            .map_err(|_| ApiError::internal("database contains invalid file size"))?,
        mime_type: row.try_get("mime_type")?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
    })
}

pub(crate) fn row_to_stored_sandbox_file(row: AnyRow) -> Result<StoredSandboxFile, ApiError> {
    let content_base64: String = row.try_get("content_base64")?;
    let content = general_purpose::STANDARD
        .decode(content_base64)
        .map_err(|_| ApiError::internal("database contains invalid file content"))?;
    Ok(StoredSandboxFile {
        file: row_to_sandbox_file(row)?,
        content,
    })
}

pub(crate) fn row_to_runtime_resource(row: AnyRow) -> Result<RuntimeResource, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let snapshot_id: Option<String> = row.try_get("snapshot_id")?;
    let resource_kind: String = row.try_get("resource_kind")?;
    let purpose: String = row.try_get("purpose")?;
    let status: String = row.try_get("status")?;
    let service_port: Option<i64> = row.try_get("service_port")?;
    let source_snapshot_id: Option<String> = row.try_get("source_snapshot_id")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let observed_at: Option<String> = row.try_get("observed_at")?;
    let last_reconciled_at: Option<String> = row.try_get("last_reconciled_at")?;
    let ready_at: Option<String> = row.try_get("ready_at")?;
    let deleted_at: Option<String> = row.try_get("deleted_at")?;

    Ok(RuntimeResource {
        id: RuntimeResourceId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        snapshot_id: snapshot_id
            .map(|snapshot_id| parse_uuid(&snapshot_id).map(SnapshotId))
            .transpose()?,
        provider: row.try_get("provider")?,
        resource_kind: parse_runtime_resource_kind(&resource_kind)?,
        purpose: parse_runtime_resource_purpose(&purpose)?,
        resource_name: row.try_get("resource_name")?,
        namespace: row.try_get("namespace")?,
        status: parse_runtime_resource_status(&status)?,
        cluster: row.try_get("cluster")?,
        storage_class: row.try_get("storage_class")?,
        snapshot_class: row.try_get("snapshot_class")?,
        storage_size: row.try_get("storage_size")?,
        runtime_image: row.try_get("runtime_image")?,
        service_port: service_port
            .map(u16::try_from)
            .transpose()
            .map_err(|_| ApiError::internal("database contains invalid service port"))?,
        target_port: row.try_get("target_port")?,
        source_snapshot_id: source_snapshot_id
            .map(|snapshot_id| parse_uuid(&snapshot_id).map(SnapshotId))
            .transpose()?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        observed_at: observed_at.map(|time| parse_timestamp(&time)).transpose()?,
        last_reconciled_at: last_reconciled_at
            .map(|time| parse_timestamp(&time))
            .transpose()?,
        ready_at: ready_at.map(|time| parse_timestamp(&time)).transpose()?,
        deleted_at: deleted_at.map(|time| parse_timestamp(&time)).transpose()?,
        error: row.try_get("error")?,
    })
}

pub(crate) fn row_to_snapshot(row: AnyRow) -> Result<Snapshot, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let inventory: String = row.try_get("inventory")?;
    let provider_metadata: String = row.try_get("provider_metadata")?;
    let created_at: String = row.try_get("created_at")?;
    let ready_at: Option<String> = row.try_get("ready_at")?;
    let expires_at: Option<String> = row.try_get("expires_at")?;

    Ok(Snapshot {
        id: SnapshotId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        status: parse_snapshot_status(&status)?,
        label: row.try_get("label")?,
        inventory: serde_json::from_str(&inventory)?,
        provider_metadata: serde_json::from_str(&provider_metadata)?,
        created_at: parse_timestamp(&created_at)?,
        ready_at: ready_at.map(|time| parse_timestamp(&time)).transpose()?,
        expires_at: expires_at.map(|time| parse_timestamp(&time)).transpose()?,
        error: row.try_get("error")?,
    })
}

pub(crate) fn row_to_desktop_session(row: AnyRow) -> Result<DesktopSession, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let access_mode: String = row.try_get("access_mode")?;
    let connection_metadata: String = row.try_get("connection_metadata")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let expires_at: Option<String> = row.try_get("expires_at")?;

    Ok(DesktopSession {
        id: DesktopSessionId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        status: parse_desktop_session_status(&status)?,
        broker: row.try_get("broker")?,
        broker_url: row.try_get("broker_url")?,
        access_mode: parse_desktop_access_mode(&access_mode)?,
        connection_metadata: serde_json::from_str(&connection_metadata)?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        expires_at: expires_at.map(|time| parse_timestamp(&time)).transpose()?,
        error: row.try_get("error")?,
    })
}

pub(crate) fn row_to_worker(row: AnyRow) -> Result<Worker, ApiError> {
    let id: String = row.try_get("id")?;
    let status: String = row.try_get("status")?;
    let capabilities: String = row.try_get("capabilities")?;
    let max_concurrent_jobs: i64 = row.try_get("max_concurrent_jobs")?;
    let labels: String = row.try_get("labels")?;
    let registered_at: String = row.try_get("registered_at")?;
    let last_heartbeat_at: Option<String> = row.try_get("last_heartbeat_at")?;

    Ok(Worker {
        id: WorkerId(parse_uuid(&id)?),
        tenant_id: row.try_get("tenant_id")?,
        name: row.try_get("name")?,
        status: parse_worker_status(&status)?,
        provider: row.try_get("provider")?,
        capabilities: serde_json::from_str::<Vec<WorkerCapability>>(&capabilities)?,
        max_concurrent_jobs: u32::try_from(max_concurrent_jobs)
            .map_err(|_| ApiError::internal("database contains invalid worker capacity"))?,
        labels: serde_json::from_str(&labels)?,
        registered_at: parse_timestamp(&registered_at)?,
        last_heartbeat_at: last_heartbeat_at
            .map(|time| parse_timestamp(&time))
            .transpose()?,
    })
}

pub(crate) fn row_to_guest_health(row: AnyRow) -> Result<GuestHealth, ApiError> {
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let last_probe_at: String = row.try_get("last_probe_at")?;
    let checks: String = row.try_get("checks")?;

    Ok(GuestHealth {
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        status: parse_guest_status(&status)?,
        last_probe_at: parse_timestamp(&last_probe_at)?,
        agent_version: row.try_get("agent_version")?,
        checks: serde_json::from_str(&checks)?,
        message: row.try_get("message")?,
    })
}

pub(crate) fn row_to_ssh_key(row: AnyRow) -> Result<SshKey, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let requested_at: String = row.try_get("requested_at")?;
    let updated_at: String = row.try_get("updated_at")?;
    let applied_at: Option<String> = row.try_get("applied_at")?;

    Ok(SshKey {
        id: SshKeyId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        public_key: row.try_get("public_key")?,
        principal: row.try_get("principal")?,
        status: parse_ssh_key_status(&status)?,
        requested_at: parse_timestamp(&requested_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        applied_at: applied_at.map(|time| parse_timestamp(&time)).transpose()?,
        error: row.try_get("error")?,
    })
}

pub(crate) fn row_to_event(row: AnyRow) -> Result<SandboxEvent, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let kind: String = row.try_get("kind")?;
    let data: String = row.try_get("data")?;
    let created_at: String = row.try_get("created_at")?;

    Ok(SandboxEvent {
        id: EventId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        kind: parse_event_kind(&kind)?,
        data: serde_json::from_str(&data)?,
        created_at: parse_timestamp(&created_at)?,
    })
}

pub(crate) fn row_to_command(row: AnyRow) -> Result<CommandRun, ApiError> {
    let id: String = row.try_get("id")?;
    let sandbox_id: String = row.try_get("sandbox_id")?;
    let status: String = row.try_get("status")?;
    let argv: String = row.try_get("argv")?;
    let created_at: String = row.try_get("created_at")?;
    let finished_at: Option<String> = row.try_get("finished_at")?;

    Ok(CommandRun {
        id: CommandId(parse_uuid(&id)?),
        sandbox_id: SandboxId(parse_uuid(&sandbox_id)?),
        status: parse_command_status(&status)?,
        argv: serde_json::from_str(&argv)?,
        cwd: row.try_get("cwd")?,
        exit_code: row.try_get("exit_code")?,
        stdout: row.try_get("stdout")?,
        stderr: row.try_get("stderr")?,
        created_at: parse_timestamp(&created_at)?,
        finished_at: finished_at.map(|time| parse_timestamp(&time)).transpose()?,
    })
}

pub(crate) fn row_to_job(row: AnyRow) -> Result<Job, ApiError> {
    let id: String = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let status: String = row.try_get("status")?;
    let payload: String = row.try_get("payload")?;
    let required_capability: String = row.try_get("required_capability")?;
    let required_execution_class: String = row.try_get("required_execution_class")?;
    let scheduled_at: String = row.try_get("scheduled_at")?;
    let created_at: String = row.try_get("created_at")?;
    let updated_at: String = row.try_get("updated_at")?;

    Ok(Job {
        id: JobId(parse_uuid(&id)?),
        tenant_id: row.try_get("tenant_id")?,
        kind: parse_job_kind(&kind)?,
        status: parse_job_status(&status)?,
        payload: serde_json::from_str(&payload)?,
        required_capability: parse_worker_capability(&required_capability)?,
        required_execution_class: ExecutionClass::parse_db_str(&required_execution_class).map_err(
            |_| ApiError::internal("database contains invalid required execution class"),
        )?,
        priority: row.try_get("priority")?,
        attempts: row.try_get("attempts")?,
        max_attempts: row.try_get("max_attempts")?,
        scheduled_at: parse_timestamp(&scheduled_at)?,
        created_at: parse_timestamp(&created_at)?,
        updated_at: parse_timestamp(&updated_at)?,
        last_error: row.try_get("last_error")?,
    })
}

pub(crate) fn row_to_command_output_chunk(row: AnyRow) -> Result<CommandOutputChunk, ApiError> {
    let id: String = row.try_get("id")?;
    let command_id: String = row.try_get("command_id")?;
    let stream: String = row.try_get("stream")?;
    let sequence: i64 = row.try_get("sequence")?;
    let annotations: String = row.try_get("annotations")?;
    let created_at: String = row.try_get("created_at")?;

    Ok(CommandOutputChunk {
        id: CommandOutputChunkId(parse_uuid(&id)?),
        command_id: CommandId(parse_uuid(&command_id)?),
        stream: parse_command_output_stream(&stream)?,
        sequence: u64::try_from(sequence)
            .map_err(|_| ApiError::internal("database contains invalid output sequence"))?,
        chunk: row.try_get("chunk")?,
        annotations: serde_json::from_str(&annotations)
            .map_err(|_| ApiError::internal("database contains invalid output annotations"))?,
        created_at: parse_timestamp(&created_at)?,
    })
}

pub(crate) fn row_to_lease_without_job(row: AnyRow) -> Result<JobLease, ApiError> {
    let id: String = row.try_get("id")?;
    let job_id: String = row.try_get("job_id")?;
    let worker_id: String = row.try_get("worker_id")?;
    let status: String = row.try_get("status")?;
    let leased_at: String = row.try_get("leased_at")?;
    let expires_at: String = row.try_get("expires_at")?;
    let completed_at: Option<String> = row.try_get("completed_at")?;

    Ok(JobLease {
        id: LeaseId(parse_uuid(&id)?),
        job_id: JobId(parse_uuid(&job_id)?),
        worker_id: WorkerId(parse_uuid(&worker_id)?),
        status: parse_lease_status(&status)?,
        attempt: row.try_get("attempt")?,
        leased_at: parse_timestamp(&leased_at)?,
        expires_at: parse_timestamp(&expires_at)?,
        completed_at: completed_at
            .map(|time| parse_timestamp(&time))
            .transpose()?,
        error: row.try_get("error")?,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        job: Job {
            id: JobId::new(),
            tenant_id: "default".to_string(),
            kind: JobKind::RunCommand,
            status: JobStatus::Queued,
            payload: json!({}),
            required_capability: WorkerCapability::RunCommand,
            required_execution_class: ExecutionClass::DevelopmentContainer,
            priority: 0,
            attempts: 0,
            max_attempts: 1,
            scheduled_at: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_error: None,
        },
    })
}

pub(crate) fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError::internal("database contains invalid uuid"))
}

pub(crate) fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| ApiError::internal("database contains invalid timestamp"))
}

pub(crate) fn state_to_str(state: &SandboxState) -> &'static str {
    state.as_db_str()
}

pub(crate) fn parse_state(value: &str) -> Result<SandboxState, ApiError> {
    parse_db_variant(value, "database contains invalid sandbox state")
}

pub(crate) fn memory_limit_to_str(memory_limit: &MemoryLimit) -> &'static str {
    memory_limit.as_db_str()
}

pub(crate) fn parse_memory_limit(value: &str) -> Result<MemoryLimit, ApiError> {
    parse_db_variant(value, "database contains invalid sandbox memory limit")
}

pub(crate) fn network_egress_mode_to_str(mode: &NetworkEgressMode) -> &'static str {
    mode.as_db_str()
}

pub(crate) fn parse_network_egress_mode(value: &str) -> Result<NetworkEgressMode, ApiError> {
    parse_db_variant(
        value,
        "database contains invalid sandbox network egress mode",
    )
}

pub(crate) fn network_allow_rule_kind_to_str(kind: &NetworkAllowRuleKind) -> &'static str {
    kind.as_db_str()
}

pub(crate) fn parse_network_allow_rule_kind(value: &str) -> Result<NetworkAllowRuleKind, ApiError> {
    parse_db_variant(value, "database contains invalid network allow rule kind")
}

pub(crate) fn snapshot_status_to_str(status: &SnapshotStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn desktop_session_status_to_str(status: &DesktopSessionStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn desktop_access_mode_to_str(access_mode: &DesktopAccessMode) -> &'static str {
    access_mode.as_db_str()
}

pub(crate) fn runtime_resource_kind_to_str(kind: &RuntimeResourceKind) -> &'static str {
    kind.as_db_str()
}

pub(crate) fn runtime_resource_purpose_to_str(purpose: &RuntimeResourcePurpose) -> &'static str {
    purpose.as_db_str()
}

pub(crate) fn runtime_resource_status_to_str(status: &RuntimeResourceStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn cleanup_run_status_to_str(status: &CleanupRunStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn command_status_to_str(status: &CommandStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn command_output_stream_to_str(stream: &CommandOutputStream) -> &'static str {
    stream.as_db_str()
}

pub(crate) fn worker_status_to_str(status: &WorkerStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn worker_capability_to_str(capability: &WorkerCapability) -> &'static str {
    capability.as_db_str()
}

pub(crate) fn job_kind_to_str(kind: &JobKind) -> &'static str {
    kind.as_db_str()
}

pub(crate) fn job_status_to_str(status: &JobStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn lease_status_to_str(status: &LeaseStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn guest_status_to_str(status: &GuestStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn ssh_key_status_to_str(status: &SshKeyStatus) -> &'static str {
    status.as_db_str()
}

pub(crate) fn event_kind_to_str(kind: &SandboxEventKind) -> &'static str {
    kind.as_db_str()
}

pub(crate) fn parse_db_variant<T: DbVariant>(
    value: &str,
    message: &'static str,
) -> Result<T, ApiError> {
    T::parse_db_str(value).map_err(|_| ApiError::internal(message))
}

pub(crate) fn parse_command_status(value: &str) -> Result<CommandStatus, ApiError> {
    parse_db_variant(value, "database contains invalid command status")
}

pub(crate) fn parse_command_output_stream(value: &str) -> Result<CommandOutputStream, ApiError> {
    parse_db_variant(value, "database contains invalid command output stream")
}

pub(crate) fn parse_snapshot_status(value: &str) -> Result<SnapshotStatus, ApiError> {
    parse_db_variant(value, "database contains invalid snapshot status")
}

pub(crate) fn parse_desktop_session_status(value: &str) -> Result<DesktopSessionStatus, ApiError> {
    parse_db_variant(value, "database contains invalid desktop session status")
}

pub(crate) fn parse_desktop_access_mode(value: &str) -> Result<DesktopAccessMode, ApiError> {
    parse_db_variant(value, "database contains invalid desktop access mode")
}

pub(crate) fn parse_runtime_resource_kind(value: &str) -> Result<RuntimeResourceKind, ApiError> {
    parse_db_variant(value, "database contains invalid runtime resource kind")
}

pub(crate) fn parse_runtime_resource_purpose(
    value: &str,
) -> Result<RuntimeResourcePurpose, ApiError> {
    parse_db_variant(value, "database contains invalid runtime resource purpose")
}

pub(crate) fn parse_runtime_resource_status(
    value: &str,
) -> Result<RuntimeResourceStatus, ApiError> {
    parse_db_variant(value, "database contains invalid runtime resource status")
}

pub(crate) fn parse_worker_capability(value: &str) -> Result<WorkerCapability, ApiError> {
    parse_db_variant(value, "database contains invalid worker capability")
}

pub(crate) fn parse_job_kind(value: &str) -> Result<JobKind, ApiError> {
    parse_db_variant(value, "database contains invalid job kind")
}

pub(crate) fn parse_job_status(value: &str) -> Result<JobStatus, ApiError> {
    parse_db_variant(value, "database contains invalid job status")
}

pub(crate) fn parse_lease_status(value: &str) -> Result<LeaseStatus, ApiError> {
    parse_db_variant(value, "database contains invalid lease status")
}

pub(crate) fn parse_guest_status(value: &str) -> Result<GuestStatus, ApiError> {
    parse_db_variant(value, "database contains invalid guest status")
}

pub(crate) fn parse_ssh_key_status(value: &str) -> Result<SshKeyStatus, ApiError> {
    parse_db_variant(value, "database contains invalid ssh key status")
}

pub(crate) fn parse_worker_status(value: &str) -> Result<WorkerStatus, ApiError> {
    parse_db_variant(value, "database contains invalid worker status")
}

pub(crate) fn parse_event_kind(value: &str) -> Result<SandboxEventKind, ApiError> {
    parse_db_variant(value, "database contains invalid event kind")
}
