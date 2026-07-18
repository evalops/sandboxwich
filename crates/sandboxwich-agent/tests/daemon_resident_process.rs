use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::post,
};
use chrono::Utc;
use sandboxwich_core::{
    ClaimLeaseResponse, CompleteLeaseRequest, ExecutionClass, FailLeaseRequest, Job, JobId,
    JobKind, JobLease, JobStatus, LeaseId, LeaseResponse, LeaseStatus,
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
    observed_pid: Arc<Mutex<Option<u32>>>,
}

impl StubState {
    fn new(leases: Vec<JobLease>, fail_observation: Option<ResidentProcessObservedState>) -> Self {
        Self {
            leases: Arc::new(Mutex::new(leases.clone().into())),
            all_leases: Arc::new(leases),
            resident_running: Arc::new(AtomicBool::new(false)),
            resident_lost: Arc::new(AtomicBool::new(false)),
            command_completed: Arc::new(AtomicBool::new(false)),
            fail_observation,
            resident_lease_failed: Arc::new(AtomicBool::new(false)),
            observed_pid: Arc::new(Mutex::new(None)),
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

async fn claim(State(state): State<StubState>) -> Json<ClaimLeaseResponse> {
    let mut leases = state.leases.lock().expect("lease queue lock");
    let lease = match leases.front() {
        Some(lease) if lease.job.kind == JobKind::RunResidentProcess => leases.pop_front(),
        Some(_) if state.resident_running.load(Ordering::SeqCst) => leases.pop_front(),
        _ => None,
    };
    Json(ClaimLeaseResponse { ok: true, lease })
}

async fn observe(
    State(state): State<StubState>,
    Json(request): Json<ResidentProcessObservationRequest>,
) -> StatusCode {
    if request.observed_state == ResidentProcessObservedState::Running {
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
    if lease.job.kind == JobKind::RunResidentProcess && request.retry {
        state.resident_lease_failed.store(true, Ordering::SeqCst);
    }
    Json(LeaseResponse { ok: true, lease })
}

async fn spawn_stub(state: StubState) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/sandboxes/{sandbox_id}/guest-health", post(health))
        .route("/workers/{worker_id}/leases/claim", post(claim))
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
                "20",
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
async fn spawn_failure_returns_the_exact_resident_lease_for_retry() {
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
    assert!(state.resident_lease_failed.load(Ordering::SeqCst));
    assert!(!state.resident_running.load(Ordering::SeqCst));
}
