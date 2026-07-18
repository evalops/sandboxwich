use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use chrono::Utc;
use sandboxwich_core::{
    ClaimLeaseResponse, CompleteLeaseRequest, ExecutionClass, FailLeaseRequest, GuestTokenResponse,
    Job, JobId, JobKind, JobLease, JobStatus, LeaseId, LeaseResponse, LeaseStatus,
    ResidentProcessObservationRequest, ResidentProcessObservedState, ResidentProcessRestartPolicy,
    SandboxId, WorkerCapability, WorkerId,
};
use tokio::{net::TcpListener, process::Command};
use uuid::Uuid;

#[derive(Clone)]
struct StubState {
    leases: Arc<Mutex<VecDeque<JobLease>>>,
    all_leases: Arc<Vec<JobLease>>,
    resident_running: Arc<AtomicBool>,
    resident_lost: Arc<AtomicBool>,
    command_completed: Arc<AtomicBool>,
    fail_observation: Option<ResidentProcessObservedState>,
    resident_lease_failed: Arc<AtomicBool>,
    resident_lease_terminally_failed: Arc<AtomicBool>,
    resident_claims: Arc<AtomicUsize>,
    observed_pid: Arc<Mutex<Option<u32>>>,
    starting_observed: Arc<AtomicBool>,
    starting_attempts: Arc<AtomicUsize>,
    starting_failures_remaining: Arc<AtomicUsize>,
    running_attempts: Arc<AtomicUsize>,
    running_failures_remaining: Arc<AtomicUsize>,
    failed_observed: Arc<AtomicBool>,
    mint_attempts: Arc<AtomicUsize>,
    claim_authorizations: Arc<Mutex<Vec<String>>>,
}

impl StubState {
    fn new(leases: Vec<JobLease>, fail_observation: Option<ResidentProcessObservedState>) -> Self {
        let fail_starting_forever =
            fail_observation == Some(ResidentProcessObservedState::Starting);
        Self {
            leases: Arc::new(Mutex::new(leases.clone().into())),
            all_leases: Arc::new(leases),
            resident_running: Arc::new(AtomicBool::new(false)),
            resident_lost: Arc::new(AtomicBool::new(false)),
            command_completed: Arc::new(AtomicBool::new(false)),
            fail_observation,
            resident_lease_failed: Arc::new(AtomicBool::new(false)),
            resident_lease_terminally_failed: Arc::new(AtomicBool::new(false)),
            resident_claims: Arc::new(AtomicUsize::new(0)),
            observed_pid: Arc::new(Mutex::new(None)),
            starting_observed: Arc::new(AtomicBool::new(false)),
            starting_attempts: Arc::new(AtomicUsize::new(0)),
            starting_failures_remaining: Arc::new(AtomicUsize::new(
                usize::from(fail_starting_forever) * usize::MAX,
            )),
            running_attempts: Arc::new(AtomicUsize::new(0)),
            running_failures_remaining: Arc::new(AtomicUsize::new(0)),
            failed_observed: Arc::new(AtomicBool::new(false)),
            mint_attempts: Arc::new(AtomicUsize::new(0)),
            claim_authorizations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn lease(&self, lease_id: &str) -> JobLease {
        self.all_leases
            .iter()
            .find(|lease| lease.id.to_string() == lease_id)
            .expect("stub must know every lease")
            .clone()
    }
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true}))
}

async fn claim(State(state): State<StubState>, headers: HeaderMap) -> Json<ClaimLeaseResponse> {
    if let Some(authorization) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        state
            .claim_authorizations
            .lock()
            .expect("claim authorizations lock")
            .push(authorization.to_string());
    }
    let mut leases = state.leases.lock().expect("lease queue lock");
    let lease = match leases.front() {
        Some(lease) if lease.job.kind == JobKind::RunResidentProcess => leases.pop_front(),
        Some(_) if state.resident_running.load(Ordering::SeqCst) => leases.pop_front(),
        _ => None,
    };
    if lease
        .as_ref()
        .is_some_and(|lease| lease.job.kind == JobKind::RunResidentProcess)
    {
        state.resident_claims.fetch_add(1, Ordering::SeqCst);
    }
    Json(ClaimLeaseResponse { ok: true, lease })
}

async fn observe(
    State(state): State<StubState>,
    Json(request): Json<ResidentProcessObservationRequest>,
) -> StatusCode {
    if request.observed_state == ResidentProcessObservedState::Starting {
        state.starting_observed.store(true, Ordering::SeqCst);
        state.starting_attempts.fetch_add(1, Ordering::SeqCst);
        if state
            .starting_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    if request.observed_state == ResidentProcessObservedState::Failed {
        state.failed_observed.store(true, Ordering::SeqCst);
    }
    if request.observed_state == ResidentProcessObservedState::Running {
        state.running_attempts.fetch_add(1, Ordering::SeqCst);
        if state
            .running_failures_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
        *state.observed_pid.lock().expect("observed pid lock") = request.pid;
    }
    if state.fail_observation.as_ref() == Some(&request.observed_state) {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    if request.observed_state == ResidentProcessObservedState::Running {
        state.resident_running.store(true, Ordering::SeqCst);
    }
    if request.observed_state == ResidentProcessObservedState::Lost {
        state.resident_lost.store(true, Ordering::SeqCst);
    }
    StatusCode::NO_CONTENT
}

async fn mint_guest_token(
    State(state): State<StubState>,
    AxumPath((worker_id, sandbox_id)): AxumPath<(String, String)>,
) -> Result<Json<GuestTokenResponse>, StatusCode> {
    let attempt = state.mint_attempts.fetch_add(1, Ordering::SeqCst);
    if attempt == 0 {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    Ok(Json(GuestTokenResponse {
        ok: true,
        token: "guest-token".into(),
        tenant_id: "test".into(),
        worker_id: WorkerId(worker_id.parse().expect("worker id path")),
        sandbox_id: SandboxId(sandbox_id.parse().expect("sandbox id path")),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    }))
}

async fn renew(
    State(state): State<StubState>,
    AxumPath(lease_id): AxumPath<String>,
) -> Json<LeaseResponse> {
    Json(LeaseResponse {
        ok: true,
        lease: state.lease(&lease_id),
    })
}

async fn complete(
    State(state): State<StubState>,
    AxumPath(lease_id): AxumPath<String>,
    Json(_request): Json<CompleteLeaseRequest>,
) -> Json<LeaseResponse> {
    let lease = state.lease(&lease_id);
    if lease.job.kind == JobKind::RunCommand {
        state.command_completed.store(true, Ordering::SeqCst);
    }
    Json(LeaseResponse { ok: true, lease })
}

async fn fail(
    State(state): State<StubState>,
    AxumPath(lease_id): AxumPath<String>,
    Json(request): Json<FailLeaseRequest>,
) -> Json<LeaseResponse> {
    let lease = state.lease(&lease_id);
    if lease.job.kind == JobKind::RunResidentProcess {
        if request.retry {
            state.resident_lease_failed.store(true, Ordering::SeqCst);
        } else {
            state
                .resident_lease_terminally_failed
                .store(true, Ordering::SeqCst);
        }
    }
    Json(LeaseResponse { ok: true, lease })
}

async fn spawn_stub(state: StubState) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/sandboxes/{sandbox_id}/guest-health", post(health))
        .route("/workers/{worker_id}/leases/claim", post(claim))
        .route(
            "/workers/{worker_id}/sandboxes/{sandbox_id}/guest-token",
            post(mint_guest_token),
        )
        .route(
            "/resident-processes/{process_id}/observations",
            post(observe),
        )
        .route("/leases/{lease_id}/renew", post(renew))
        .route("/leases/{lease_id}/complete", post(complete))
        .route("/leases/{lease_id}/fail", post(fail))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral stub");
    let address = listener.local_addr().expect("stub address");
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve API stub");
    });
    (format!("http://{address}"), task)
}

fn lease(worker_id: WorkerId, kind: JobKind, payload: serde_json::Value) -> JobLease {
    let now = Utc::now();
    let job_id = JobId::new();
    JobLease {
        id: LeaseId::new(),
        job_id,
        worker_id,
        status: LeaseStatus::Active,
        attempt: 1,
        leased_at: now,
        expires_at: now + chrono::Duration::seconds(60),
        completed_at: None,
        error: None,
        required_execution_class: ExecutionClass::DevelopmentContainer,
        job: Job {
            id: job_id,
            tenant_id: "test".into(),
            kind,
            status: JobStatus::Leased,
            payload,
            required_capability: WorkerCapability::RunCommand,
            required_execution_class: ExecutionClass::DevelopmentContainer,
            priority: 0,
            attempts: 1,
            max_attempts: 3,
            scheduled_at: now,
            created_at: now,
            updated_at: now,
            last_error: None,
        },
    }
}

async fn run_daemon(api: &str, worker_id: WorkerId, sandbox_id: SandboxId) -> std::process::Output {
    run_daemon_for_iterations(api, worker_id, sandbox_id, 20).await
}

async fn run_daemon_for_iterations(
    api: &str,
    worker_id: WorkerId,
    sandbox_id: SandboxId,
    max_iterations: u64,
) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(15),
        Command::new(env!("CARGO_BIN_EXE_sandboxwich-agent"))
            .args([
                "daemon",
                "--api",
                api,
                "--api-token",
                "worker-token",
                "--guest-token",
                "guest-token",
                "--worker-id",
                &worker_id.to_string(),
                "--sandbox-id",
                &sandbox_id.to_string(),
                "--heartbeat-interval-ms",
                "60000",
                "--idle-sleep-ms",
                "10",
                "--max-iterations",
                &max_iterations.to_string(),
            ])
            .output(),
    )
    .await
    .expect("daemon must exit deterministically")
    .expect("spawn daemon")
}

async fn run_daemon_with_self_minted_guest_token(
    api: &str,
    worker_id: WorkerId,
    sandbox_id: SandboxId,
) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(15),
        Command::new(env!("CARGO_BIN_EXE_sandboxwich-agent"))
            .args([
                "daemon",
                "--api",
                api,
                "--api-token",
                "worker-token",
                "--worker-id",
                &worker_id.to_string(),
                "--sandbox-id",
                &sandbox_id.to_string(),
                "--heartbeat-interval-ms",
                "60000",
                "--idle-sleep-ms",
                "1",
                "--max-iterations",
                "1",
            ])
            .output(),
    )
    .await
    .expect("daemon must exit deterministically")
    .expect("spawn daemon")
}

fn process_exists(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .status()
        .is_ok_and(|status| status.success())
}

#[tokio::test]
async fn daemon_runs_commands_while_resident_is_alive_and_reaps_it_on_shutdown() {
    let worker_id = WorkerId::new();
    let sandbox_id = SandboxId(Uuid::now_v7());
    let process_id = Uuid::now_v7();
    let pid_file = std::env::temp_dir().join(format!("sandboxwich-resident-{process_id}.pid"));
    let resident = lease(
        worker_id,
        JobKind::RunResidentProcess,
        serde_json::json!({
            "sandboxId": sandbox_id,
            "residentProcessId": process_id,
            "generation": 1,
            "name": "orb-executor",
            "argv": ["sh", "-c", format!("echo $$ > {}; exec sleep 60", pid_file.display())],
            "restartPolicy": ResidentProcessRestartPolicy::Never,
        }),
    );
    let command = lease(
        worker_id,
        JobKind::RunCommand,
        serde_json::json!({
            "sandboxId": sandbox_id,
            "argv": ["sh", "-c", "exit 0"],
            "timeoutSecs": 5,
        }),
    );
    let state = StubState::new(vec![resident, command], None);
    let (api, server) = spawn_stub(state.clone()).await;

    let output = run_daemon(&api, worker_id, sandbox_id).await;
    server.abort();

    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(state.resident_running.load(Ordering::SeqCst));
    assert!(
        state.resident_lost.load(Ordering::SeqCst),
        "daemon shutdown must publish a Lost observation before returning the lease"
    );
    assert!(
        state.command_completed.load(Ordering::SeqCst),
        "daemon must claim and complete ordinary work while the resident remains alive"
    );
    let pid = std::fs::read_to_string(&pid_file).expect("resident wrote its pid");
    assert!(
        !process_exists(pid.trim()),
        "resident child {pid:?} survived daemon shutdown"
    );
    let _ = std::fs::remove_file(pid_file);
}

#[tokio::test]
async fn daemon_fails_the_exact_resident_lease_when_observation_rejects_startup() {
    let worker_id = WorkerId::new();
    let sandbox_id = SandboxId(Uuid::now_v7());
    let resident = lease(
        worker_id,
        JobKind::RunResidentProcess,
        serde_json::json!({
            "sandboxId": sandbox_id,
            "residentProcessId": Uuid::now_v7(),
            "generation": 7,
            "name": "orb-executor",
            "argv": ["sh", "-c", "exec sleep 60"],
            "restartPolicy": ResidentProcessRestartPolicy::Never,
        }),
    );
    let state = StubState::new(vec![resident], Some(ResidentProcessObservedState::Starting));
    let (api, server) = spawn_stub(state.clone()).await;

    let output = run_daemon(&api, worker_id, sandbox_id).await;
    server.abort();

    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        state.resident_lease_failed.load(Ordering::SeqCst),
        "resident task failure must fail the exact lease with retry=true"
    );
    assert!(!state.resident_running.load(Ordering::SeqCst));
}

#[tokio::test]
async fn rejected_running_observation_kills_the_spawned_child_and_fails_its_lease() {
    let worker_id = WorkerId::new();
    let sandbox_id = SandboxId(Uuid::now_v7());
    let resident = lease(
        worker_id,
        JobKind::RunResidentProcess,
        serde_json::json!({
            "sandboxId": sandbox_id,
            "residentProcessId": Uuid::now_v7(),
            "generation": 3,
            "name": "orb-executor",
            "argv": ["sh", "-c", "exec sleep 60"],
            "restartPolicy": ResidentProcessRestartPolicy::Never,
        }),
    );
    let state = StubState::new(vec![resident], Some(ResidentProcessObservedState::Running));
    let (api, server) = spawn_stub(state.clone()).await;

    let output = run_daemon(&api, worker_id, sandbox_id).await;
    server.abort();

    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(state.resident_lease_failed.load(Ordering::SeqCst));
    let pid = state
        .observed_pid
        .lock()
        .expect("observed pid lock")
        .expect("Running observation carried a child pid");
    assert!(
        !process_exists(&pid.to_string()),
        "resident child {pid} survived observation failure"
    );
}

#[tokio::test]
async fn transient_starting_observation_retries_on_the_same_resident_lease() {
    let worker_id = WorkerId::new();
    let sandbox_id = SandboxId(Uuid::now_v7());
    let resident = lease(
        worker_id,
        JobKind::RunResidentProcess,
        serde_json::json!({
            "sandboxId": sandbox_id,
            "residentProcessId": Uuid::now_v7(),
            "generation": 5,
            "name": "orb-executor",
            "argv": ["sh", "-c", "exec sleep 60"],
            "restartPolicy": ResidentProcessRestartPolicy::Never,
        }),
    );
    let state = StubState::new(vec![resident], None);
    state.starting_failures_remaining.store(1, Ordering::SeqCst);
    let (api, server) = spawn_stub(state.clone()).await;

    let output = run_daemon_for_iterations(&api, worker_id, sandbox_id, 40).await;
    server.abort();

    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        state.starting_attempts.load(Ordering::SeqCst),
        2,
        "Starting must retry under the original renewing lease after a transient outage"
    );
    assert!(
        state.resident_running.load(Ordering::SeqCst),
        "the original resident child should continue through the recovered Starting observation"
    );
}

#[tokio::test]
async fn transient_running_observation_retries_on_the_same_acknowledged_lease() {
    let worker_id = WorkerId::new();
    let sandbox_id = SandboxId(Uuid::now_v7());
    let resident = lease(
        worker_id,
        JobKind::RunResidentProcess,
        serde_json::json!({
            "sandboxId": sandbox_id,
            "residentProcessId": Uuid::now_v7(),
            "generation": 6,
            "name": "orb-executor",
            "argv": ["sh", "-c", "exec sleep 60"],
            "restartPolicy": ResidentProcessRestartPolicy::Never,
        }),
    );
    let state = StubState::new(vec![resident], None);
    state.running_failures_remaining.store(1, Ordering::SeqCst);
    let (api, server) = spawn_stub(state.clone()).await;

    let output = run_daemon_for_iterations(&api, worker_id, sandbox_id, 40).await;
    server.abort();

    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        state.running_attempts.load(Ordering::SeqCst),
        2,
        "Running must retry on the acknowledged lease instead of failing it for a new fence"
    );
    assert!(state.resident_running.load(Ordering::SeqCst));
}

#[tokio::test]
async fn spawn_failure_terminally_reconciles_the_consumed_bootstrap_lease() {
    let worker_id = WorkerId::new();
    let sandbox_id = SandboxId(Uuid::now_v7());
    let resident = lease(
        worker_id,
        JobKind::RunResidentProcess,
        serde_json::json!({
            "sandboxId": sandbox_id,
            "residentProcessId": Uuid::now_v7(),
            "generation": 4,
            "name": "orb-executor",
            "argv": ["/definitely/missing/sandboxwich-resident"],
            "restartPolicy": ResidentProcessRestartPolicy::Never,
        }),
    );
    let state = StubState::new(vec![resident], None);
    let (api, server) = spawn_stub(state.clone()).await;

    let output = run_daemon(&api, worker_id, sandbox_id).await;
    server.abort();

    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        state
            .resident_lease_terminally_failed
            .load(Ordering::SeqCst),
        "acknowledged bootstrap delivery followed by a final spawn failure must be terminal"
    );
    assert!(
        !state.resident_lease_failed.load(Ordering::SeqCst),
        "the agent must not promise a retry after bootstrap bytes have been consumed"
    );
    assert_eq!(
        state.resident_claims.load(Ordering::SeqCst),
        1,
        "terminally failing the consumed-bootstrap lease must not require a replacement lease"
    );
    assert!(!state.resident_running.load(Ordering::SeqCst));
    assert!(
        !state.starting_observed.load(Ordering::SeqCst),
        "Starting must not be acknowledged before the fallible process spawn"
    );
    assert!(
        state.failed_observed.load(Ordering::SeqCst),
        "a spawn failure must be terminally acknowledged as Failed before its consumed lease closes"
    );
}

#[tokio::test]
async fn daemon_retries_guest_token_mint_before_claiming_with_the_guest_credential() {
    let worker_id = WorkerId::new();
    let sandbox_id = SandboxId(Uuid::now_v7());
    let state = StubState::new(Vec::new(), None);
    let (api, server) = spawn_stub(state.clone()).await;

    let output = run_daemon_with_self_minted_guest_token(&api, worker_id, sandbox_id).await;
    server.abort();

    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        state.mint_attempts.load(Ordering::SeqCst),
        2,
        "the first transient mint failure must be retried instead of pinning the worker client"
    );
    assert_eq!(
        state
            .claim_authorizations
            .lock()
            .expect("claim authorizations lock")
            .as_slice(),
        ["Bearer guest-token"],
        "the daemon must not claim executor work with the broader worker token"
    );
}
