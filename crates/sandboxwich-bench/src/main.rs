use std::{
    fs::{self, File},
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use chrono::Utc;
use reqwest::StatusCode;
use sandboxwich_core::{
    CapacityResponse, CommandOutputListResponse, CommandRequest, CommandResponse, CommandStatus,
    CreateJobRequest, CreateSandboxRequest, JobId, JobKind, JobResponse, JobStatus, SandboxId,
    SandboxResponse, WorkerCapability,
};
use serde::de::DeserializeOwned;
use sqlx::{AnyPool, any::AnyPoolOptions};
use tokio::sync::mpsc;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse(std::env::args().skip(1).collect())?;
    match args.command {
        BenchCommand::All(options) => run_all(options).await,
        BenchCommand::Startup(options) => {
            let summary = benchmark_startup(&options).await?;
            println!("{}", summary.markdown("Startup"));
            Ok(())
        }
        BenchCommand::Http(options) => {
            let summary = benchmark_http(&options).await?;
            println!(
                "{}",
                summary.markdown(&format!("{} {}", options.method, options.path))
            );
            Ok(())
        }
        BenchCommand::SandboxTtft(options) => {
            let report = benchmark_sandbox_ttft(&options).await?;
            println!("{}", report.markdown("Sandbox TTFT (dry-run k8s worker)"));
            Ok(())
        }
        BenchCommand::Seed(options) => seed_database(&options).await,
    }
}

struct Args {
    command: BenchCommand,
}

enum BenchCommand {
    All(AllOptions),
    Startup(StartupOptions),
    Http(HttpOptions),
    SandboxTtft(SandboxTtftOptions),
    Seed(SeedOptions),
}

#[derive(Clone)]
struct AllOptions {
    api_bin: PathBuf,
    worker_bin: PathBuf,
    runs: usize,
    ttft_runs: usize,
    requests: usize,
    concurrency: usize,
    seed: SeedOptions,
}

#[derive(Clone)]
struct StartupOptions {
    api_bin: PathBuf,
    database_url: String,
    runs: usize,
    auto_migrate: bool,
}

#[derive(Clone)]
struct HttpOptions {
    api_url: String,
    method: HttpMethod,
    path: String,
    requests: usize,
    concurrency: usize,
}

#[derive(Clone)]
struct SeedOptions {
    database_url: String,
    sandboxes: usize,
    commands_per_sandbox: usize,
    events_per_sandbox: usize,
    runtime_resources_per_sandbox: usize,
    workers: usize,
    jobs: usize,
}

#[derive(Clone)]
struct SandboxTtftOptions {
    api_bin: PathBuf,
    worker_bin: PathBuf,
    runs: usize,
    poll_interval: Duration,
    timeout: Duration,
}

#[derive(Clone, Copy)]
enum HttpMethod {
    Get,
    PostSandbox,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => f.write_str("GET"),
            Self::PostSandbox => f.write_str("POST"),
        }
    }
}

impl Args {
    fn parse(raw: Vec<String>) -> anyhow::Result<Self> {
        let mut parser = ArgParser::new(raw);
        let command = match parser.next().as_deref() {
            None | Some("all") => BenchCommand::All(AllOptions {
                api_bin: parser
                    .path_opt("--api-bin")?
                    .unwrap_or_else(default_api_binary),
                worker_bin: parser
                    .path_opt("--worker-bin")?
                    .unwrap_or_else(default_worker_binary),
                runs: parser.usize_opt("--runs", 5)?,
                ttft_runs: parser.usize_opt("--ttft-runs", 10)?,
                requests: parser.usize_opt("--requests", 500)?,
                concurrency: parser.usize_opt("--concurrency", 25)?,
                seed: SeedOptions {
                    database_url: String::new(),
                    sandboxes: parser.usize_opt("--seed-sandboxes", 250)?,
                    commands_per_sandbox: parser.usize_opt("--commands-per-sandbox", 2)?,
                    events_per_sandbox: parser.usize_opt("--events-per-sandbox", 2)?,
                    runtime_resources_per_sandbox: parser
                        .usize_opt("--runtime-resources-per-sandbox", 2)?,
                    workers: parser.usize_opt("--workers", 8)?,
                    jobs: parser.usize_opt("--jobs", 250)?,
                },
            }),
            Some("startup") => BenchCommand::Startup(StartupOptions {
                api_bin: parser
                    .path_opt("--api-bin")?
                    .unwrap_or_else(default_api_binary),
                database_url: parser.required("--database-url")?,
                runs: parser.usize_opt("--runs", 10)?,
                auto_migrate: parser.bool_opt("--auto-migrate", false)?,
            }),
            Some("http") => BenchCommand::Http(HttpOptions {
                api_url: parser.required("--api-url")?,
                method: parser
                    .opt("--method")?
                    .map(|value| match value.as_str() {
                        "get" => Ok(HttpMethod::Get),
                        "post-sandbox" => Ok(HttpMethod::PostSandbox),
                        _ => bail!("unsupported --method {value:?}"),
                    })
                    .transpose()?
                    .unwrap_or(HttpMethod::Get),
                path: parser
                    .opt("--path")?
                    .unwrap_or_else(|| "/healthz".to_string()),
                requests: parser.usize_opt("--requests", 1000)?,
                concurrency: parser.usize_opt("--concurrency", 25)?,
            }),
            Some("sandbox-ttft") => BenchCommand::SandboxTtft(SandboxTtftOptions {
                api_bin: parser
                    .path_opt("--api-bin")?
                    .unwrap_or_else(default_api_binary),
                worker_bin: parser
                    .path_opt("--worker-bin")?
                    .unwrap_or_else(default_worker_binary),
                runs: parser.usize_opt("--runs", 10)?,
                poll_interval: Duration::from_millis(
                    parser.usize_opt("--poll-interval-ms", 5)? as u64
                ),
                timeout: Duration::from_millis(parser.usize_opt("--timeout-ms", 10_000)? as u64),
            }),
            Some("seed") => BenchCommand::Seed(SeedOptions {
                database_url: parser.required("--database-url")?,
                sandboxes: parser.usize_opt("--sandboxes", 1000)?,
                commands_per_sandbox: parser.usize_opt("--commands-per-sandbox", 2)?,
                events_per_sandbox: parser.usize_opt("--events-per-sandbox", 2)?,
                runtime_resources_per_sandbox: parser
                    .usize_opt("--runtime-resources-per-sandbox", 2)?,
                workers: parser.usize_opt("--workers", 8)?,
                jobs: parser.usize_opt("--jobs", 1000)?,
            }),
            Some("--help") | Some("-h") => {
                println!(
                    "usage: sandboxwich-bench [all|startup|http|sandbox-ttft|seed]\n\
                     examples:\n\
                       sandboxwich-bench all --api-bin target/debug/sandboxwich-api --worker-bin target/debug/sandboxwich-worker\n\
                     sandboxwich-bench startup --database-url sqlite:///tmp/bench.db\n\
                     sandboxwich-bench http --api-url http://127.0.0.1:3217 --path /readyz\n\
                       sandboxwich-bench sandbox-ttft --api-bin target/debug/sandboxwich-api --worker-bin target/debug/sandboxwich-worker\n\
                     sandboxwich-bench seed --database-url sqlite:///tmp/bench.db"
                );
                std::process::exit(0);
            }
            Some(command) => bail!("unknown benchmark command {command:?}"),
        };
        parser.finish()?;
        Ok(Self { command })
    }
}

struct ArgParser {
    args: Vec<String>,
    index: usize,
}

impl ArgParser {
    fn new(args: Vec<String>) -> Self {
        Self { args, index: 0 }
    }

    fn next(&mut self) -> Option<String> {
        let value = self.args.get(self.index).cloned();
        if value.is_some() {
            self.index += 1;
        }
        value
    }

    fn required(&mut self, name: &'static str) -> anyhow::Result<String> {
        self.opt(name)?
            .with_context(|| format!("missing required {name}"))
    }

    fn opt(&mut self, name: &'static str) -> anyhow::Result<Option<String>> {
        if let Some(offset) = self.args[self.index..].iter().position(|arg| arg == name) {
            let flag = self.index + offset;
            if flag + 1 >= self.args.len() {
                bail!("{name} requires a value");
            }
            let value = self.args.remove(flag + 1);
            self.args.remove(flag);
            return Ok(Some(value));
        }
        Ok(None)
    }

    fn path_opt(&mut self, name: &'static str) -> anyhow::Result<Option<PathBuf>> {
        Ok(self.opt(name)?.map(PathBuf::from))
    }

    fn usize_opt(&mut self, name: &'static str, default: usize) -> anyhow::Result<usize> {
        let Some(value) = self.opt(name)? else {
            return Ok(default);
        };
        value
            .parse()
            .with_context(|| format!("invalid {name} value {value:?}"))
    }

    fn bool_opt(&mut self, name: &'static str, default: bool) -> anyhow::Result<bool> {
        let Some(value) = self.opt(name)? else {
            return Ok(default);
        };
        match value.as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => bail!("invalid {name} value {value:?}"),
        }
    }

    fn finish(&self) -> anyhow::Result<()> {
        if let Some(extra) = self.args.get(self.index) {
            bail!("unexpected argument {extra:?}");
        }
        Ok(())
    }
}

fn default_api_binary() -> PathBuf {
    PathBuf::from("target/debug/sandboxwich-api")
}

fn default_worker_binary() -> PathBuf {
    PathBuf::from("target/debug/sandboxwich-worker")
}

async fn run_all(mut options: AllOptions) -> anyhow::Result<()> {
    let bench_id = Uuid::now_v7().to_string();
    let db_path = std::env::temp_dir().join(format!("sandboxwich-bench-{bench_id}.db"));
    let database_url = format!("sqlite://{}", db_path.display());
    run_api_command(&options.api_bin, "migrate", &database_url)?;
    options.seed.database_url = database_url.clone();
    seed_database(&options.seed).await?;

    let startup = benchmark_startup(&StartupOptions {
        api_bin: options.api_bin.clone(),
        database_url: database_url.clone(),
        runs: options.runs,
        auto_migrate: false,
    })
    .await?;

    let mut server = ApiProcess::start(&options.api_bin, &database_url, false).await?;
    let healthz = benchmark_http(&HttpOptions {
        api_url: server.base_url.clone(),
        method: HttpMethod::Get,
        path: "/healthz".to_string(),
        requests: options.requests,
        concurrency: options.concurrency,
    })
    .await?;
    let readyz = benchmark_http(&HttpOptions {
        api_url: server.base_url.clone(),
        method: HttpMethod::Get,
        path: "/readyz".to_string(),
        requests: options.requests,
        concurrency: options.concurrency,
    })
    .await?;
    let sandboxes = benchmark_http(&HttpOptions {
        api_url: server.base_url.clone(),
        method: HttpMethod::Get,
        path: "/sandboxes".to_string(),
        requests: options.requests,
        concurrency: options.concurrency,
    })
    .await?;
    let creates = benchmark_http(&HttpOptions {
        api_url: server.base_url.clone(),
        method: HttpMethod::PostSandbox,
        path: "/sandboxes".to_string(),
        requests: options.requests.min(250),
        concurrency: options.concurrency.min(20),
    })
    .await?;
    server.stop();
    let _ = fs::remove_file(db_path);

    let sandbox_ttft = if options.ttft_runs == 0 {
        None
    } else {
        // TTFT uses a fresh DB so seeded benchmark data cannot affect worker claim timing.
        Some(
            benchmark_sandbox_ttft(&SandboxTtftOptions {
                api_bin: options.api_bin.clone(),
                worker_bin: options.worker_bin.clone(),
                runs: options.ttft_runs,
                poll_interval: Duration::from_millis(5),
                timeout: Duration::from_secs(10),
            })
            .await?,
        )
    };

    println!("# Sandboxwich Benchmark Report");
    println!();
    println!("- profile: debug");
    println!("- database: SQLite");
    println!("- seeded sandboxes: {}", options.seed.sandboxes);
    println!(
        "- commands per sandbox: {}",
        options.seed.commands_per_sandbox
    );
    println!(
        "- runtime resources per sandbox: {}",
        options.seed.runtime_resources_per_sandbox
    );
    println!();
    println!("{}", startup.markdown("warm startup"));
    println!("{}", healthz.markdown("GET /healthz"));
    println!("{}", readyz.markdown("GET /readyz"));
    println!("{}", sandboxes.markdown("GET /sandboxes"));
    println!("{}", creates.markdown("POST /sandboxes"));
    if let Some(report) = sandbox_ttft {
        println!("{}", report.markdown("Sandbox TTFT (dry-run k8s worker)"));
    }
    Ok(())
}

fn run_api_command(api_bin: &PathBuf, command: &str, database_url: &str) -> anyhow::Result<()> {
    let status = Command::new(api_bin)
        .arg(command)
        .env("SANDBOXWICH_DATABASE_URL", database_url)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to run {}", api_bin.display()))?;
    if !status.success() {
        bail!("{command} command failed with {status}");
    }
    Ok(())
}

struct ApiProcess {
    child: Child,
    base_url: String,
    stderr_path: PathBuf,
}

impl ApiProcess {
    async fn start(
        api_bin: &PathBuf,
        database_url: &str,
        auto_migrate: bool,
    ) -> anyhow::Result<Self> {
        let addr = free_addr()?;
        let stderr_path = process_log_path("api");
        let stderr = File::create(&stderr_path)
            .with_context(|| format!("failed to create {}", stderr_path.display()))?;
        let mut child = Command::new(api_bin)
            .env("SANDBOXWICH_DATABASE_URL", database_url)
            .env("SANDBOXWICH_BIND", addr.to_string())
            .env(
                "SANDBOXWICH_AUTO_MIGRATE",
                if auto_migrate { "true" } else { "false" },
            )
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .with_context(|| format!("failed to start {}", api_bin.display()))?;

        let base_url = format!("http://{addr}");
        if let Err(error) = wait_for_health(&base_url, &mut child, &stderr_path).await {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&stderr_path);
            return Err(error);
        }
        Ok(Self {
            child,
            base_url,
            stderr_path,
        })
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.stderr_path);
    }
}

impl Drop for ApiProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

struct WorkerProcess {
    child: Child,
    stderr_path: PathBuf,
}

impl WorkerProcess {
    async fn start(worker_bin: &PathBuf, api_url: &str) -> anyhow::Result<Self> {
        let stderr_path = process_log_path("worker");
        let stderr = File::create(&stderr_path)
            .with_context(|| format!("failed to create {}", stderr_path.display()))?;
        let child = Command::new(worker_bin)
            .arg("--api")
            .arg(api_url)
            .arg("run")
            .arg("--name")
            .arg(format!("bench-ttft-{}", Uuid::now_v7()))
            .arg("--provider")
            .arg("kubernetes")
            .arg("--cluster")
            .arg("k3s-bench")
            .arg("--namespace")
            .arg("sandboxwich-bench")
            .arg("--idle-sleep-ms")
            .arg("5")
            .arg("--max-concurrent-jobs")
            .arg("1")
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .with_context(|| format!("failed to start {}", worker_bin.display()))?;
        Ok(Self { child, stderr_path })
    }

    fn ensure_running(&mut self) -> anyhow::Result<()> {
        if let Some(status) = self.child.try_wait()? {
            bail!(
                "worker exited before benchmark completed: {status}\nstderr:\n{}",
                process_stderr(&self.stderr_path)
            );
        }
        Ok(())
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.stderr_path);
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn process_log_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sandboxwich-bench-{name}-{}.stderr.log",
        Uuid::now_v7()
    ))
}

fn process_stderr(path: &PathBuf) -> String {
    let stderr = fs::read_to_string(path).unwrap_or_else(|error| {
        format!(
            "failed to read process stderr at {}: {error}",
            path.display()
        )
    });
    if stderr.trim().is_empty() {
        "(empty)".to_string()
    } else {
        stderr
    }
}

async fn wait_for_health(
    base_url: &str,
    child: &mut Child,
    stderr_path: &PathBuf,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    for _ in 0..700 {
        if client
            .get(format!("{base_url}/healthz"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!(
                "api exited before becoming healthy: {status}\nstderr:\n{}",
                process_stderr(stderr_path)
            );
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    bail!(
        "api did not become healthy\nstderr:\n{}",
        process_stderr(stderr_path)
    );
}

fn free_addr() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

async fn benchmark_startup(options: &StartupOptions) -> anyhow::Result<BenchSummary> {
    let mut durations = Vec::with_capacity(options.runs);
    for _ in 0..options.runs {
        let started = Instant::now();
        let mut process = ApiProcess::start(
            &options.api_bin,
            &options.database_url,
            options.auto_migrate,
        )
        .await?;
        durations.push(started.elapsed());
        process.stop();
    }
    Ok(BenchSummary::from_durations(durations, 0))
}

async fn benchmark_http(options: &HttpOptions) -> anyhow::Result<BenchSummary> {
    let client = reqwest::Client::new();
    let next = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let (tx, mut rx) = mpsc::channel(options.requests);
    let url = format!("{}{}", options.api_url.trim_end_matches('/'), options.path);

    for _ in 0..options.concurrency.max(1) {
        let client = client.clone();
        let next = Arc::clone(&next);
        let tx = tx.clone();
        let url = url.clone();
        let method = options.method;
        let requests = options.requests;
        tokio::spawn(async move {
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= requests {
                    break;
                }
                let started = Instant::now();
                let status = send_request(&client, method, &url, index).await;
                let _ = tx.send((started.elapsed(), status)).await;
            }
        });
    }
    drop(tx);

    let mut durations = Vec::with_capacity(options.requests);
    let mut failures = 0;
    while let Some((duration, status)) = rx.recv().await {
        durations.push(duration);
        if !status.is_success() {
            failures += 1;
        }
    }

    let mut summary = BenchSummary::from_durations(durations, failures);
    summary.elapsed = started.elapsed();
    Ok(summary)
}

async fn benchmark_sandbox_ttft(options: &SandboxTtftOptions) -> anyhow::Result<SandboxTtftReport> {
    let bench_id = Uuid::now_v7().to_string();
    let db_path = std::env::temp_dir().join(format!("sandboxwich-ttft-{bench_id}.db"));
    let database_url = format!("sqlite://{}", db_path.display());
    run_api_command(&options.api_bin, "migrate", &database_url)?;

    let mut server = ApiProcess::start(&options.api_bin, &database_url, false).await?;
    let mut worker = WorkerProcess::start(&options.worker_bin, &server.base_url).await?;
    let client = reqwest::Client::new();
    wait_for_worker_capacity(
        &client,
        &server.base_url,
        &mut worker,
        options.timeout,
        options.poll_interval,
    )
    .await?;

    let mut samples = Vec::with_capacity(options.runs);
    for index in 0..options.runs {
        samples.push(
            run_sandbox_ttft_once(&client, &server.base_url, &mut worker, options, index).await?,
        );
    }

    worker.stop();
    server.stop();
    let _ = fs::remove_file(db_path);

    Ok(SandboxTtftReport { samples })
}

async fn run_sandbox_ttft_once(
    client: &reqwest::Client,
    base_url: &str,
    worker: &mut WorkerProcess,
    options: &SandboxTtftOptions,
    index: usize,
) -> anyhow::Result<SandboxTtftSample> {
    let total_started = Instant::now();

    let started = Instant::now();
    let sandbox: SandboxResponse = post_json(
        client
            .post(format!("{}/sandboxes", base_url.trim_end_matches('/')))
            .json(&CreateSandboxRequest {
                name: Some(format!("ttft-bench-{index}")),
                template: Some("ubuntu-dev".to_string()),
                memory_limit: None,
                network_egress: None,
                ttl_seconds: Some(120),
            }),
    )
    .await?;
    let create_sandbox = started.elapsed();
    let sandbox_id = sandbox.sandbox.id;

    let started = Instant::now();
    let provision_job = create_provision_job(client, base_url, sandbox_id).await?;
    let queue_provision = started.elapsed();

    let started = Instant::now();
    wait_for_job_status(
        client,
        base_url,
        worker,
        provision_job.job.id,
        JobStatus::Succeeded,
        options.timeout,
        options.poll_interval,
    )
    .await?;
    let provision_ready = started.elapsed();

    let started = Instant::now();
    let command: CommandResponse = post_json(
        client
            .post(format!(
                "{}/sandboxes/{sandbox_id}/commands",
                base_url.trim_end_matches('/')
            ))
            .json(&CommandRequest {
                argv: vec!["printf".to_string(), "sandboxwich-ttft\n".to_string()],
                cwd: None,
                env: Default::default(),
            }),
    )
    .await?;
    let queue_command = started.elapsed();

    let started = Instant::now();
    wait_for_first_output_chunk(
        client,
        base_url,
        worker,
        command.command.id,
        options.timeout,
        options.poll_interval,
    )
    .await?;
    let first_output = started.elapsed();

    Ok(SandboxTtftSample {
        create_sandbox,
        queue_provision,
        provision_ready,
        queue_command,
        first_output,
        total: total_started.elapsed(),
    })
}

async fn create_provision_job(
    client: &reqwest::Client,
    base_url: &str,
    sandbox_id: SandboxId,
) -> anyhow::Result<sandboxwich_core::JobResponse> {
    post_json(
        client
            .post(format!("{}/jobs", base_url.trim_end_matches('/')))
            .json(&CreateJobRequest {
                kind: JobKind::ProvisionSandbox,
                payload: serde_json::json!({ "sandboxId": sandbox_id }),
                required_capability: WorkerCapability::ProvisionSandbox,
                priority: Some(100),
                max_attempts: Some(1),
            }),
    )
    .await
}

async fn wait_for_worker_capacity(
    client: &reqwest::Client,
    base_url: &str,
    worker: &mut WorkerProcess,
    timeout: Duration,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        worker.ensure_running()?;
        if started.elapsed() > timeout {
            bail!("worker did not report available capacity within {timeout:?}");
        }

        let capacity = get_json::<CapacityResponse>(
            client,
            &format!("{}/capacity", base_url.trim_end_matches('/')),
        )
        .await;
        if let Ok(capacity) = capacity {
            if capacity.total_available_slots > 0 {
                return Ok(());
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_job_status(
    client: &reqwest::Client,
    base_url: &str,
    worker: &mut WorkerProcess,
    job_id: JobId,
    expected: JobStatus,
    timeout: Duration,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        worker.ensure_running()?;
        if started.elapsed() > timeout {
            bail!("job {job_id} did not reach {expected:?} within {timeout:?}");
        }

        let response = get_json::<JobResponse>(
            client,
            &format!("{}/jobs/{job_id}", base_url.trim_end_matches('/')),
        )
        .await?;
        let job = response.job;
        if job.status == expected {
            return Ok(());
        }
        if matches!(&job.status, JobStatus::Failed | JobStatus::Dead) {
            bail!(
                "job {job_id} reached terminal status {:?}: {}",
                job.status,
                job.last_error
                    .unwrap_or_else(|| "no error recorded".to_string())
            );
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn wait_for_first_output_chunk(
    client: &reqwest::Client,
    base_url: &str,
    worker: &mut WorkerProcess,
    command_id: sandboxwich_core::CommandId,
    timeout: Duration,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        worker.ensure_running()?;
        if started.elapsed() > timeout {
            bail!("command {command_id} did not produce output within {timeout:?}");
        }

        let output = get_json::<CommandOutputListResponse>(
            client,
            &format!(
                "{}/commands/{command_id}/output",
                base_url.trim_end_matches('/')
            ),
        )
        .await?;
        if !output.chunks.is_empty() {
            return Ok(());
        }

        let command = get_json::<CommandResponse>(
            client,
            &format!("{}/commands/{command_id}", base_url.trim_end_matches('/')),
        )
        .await?;
        match command.command.status {
            CommandStatus::Failed => bail!("command {command_id} failed before producing output"),
            CommandStatus::Finished => {
                let output = get_json::<CommandOutputListResponse>(
                    client,
                    &format!(
                        "{}/commands/{command_id}/output",
                        base_url.trim_end_matches('/')
                    ),
                )
                .await?;
                if !output.chunks.is_empty() {
                    return Ok(());
                }
                bail!("command {command_id} finished without output");
            }
            CommandStatus::Queued | CommandStatus::Running => {}
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn get_json<T>(client: &reqwest::Client, url: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    decode_json(client.get(url).send().await?).await
}

async fn post_json<T>(request: reqwest::RequestBuilder) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    decode_json(request.send().await?).await
}

async fn decode_json<T>(response: reqwest::Response) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read response body")?;
    if !status.is_success() {
        bail!("request failed with {status}: {body}");
    }
    serde_json::from_str(&body).context("failed to decode response body")
}

async fn send_request(
    client: &reqwest::Client,
    method: HttpMethod,
    url: &str,
    index: usize,
) -> StatusCode {
    let response = match method {
        HttpMethod::Get => client.get(url).send().await,
        HttpMethod::PostSandbox => {
            client
                .post(url)
                .json(&serde_json::json!({
                    "name": format!("bench-{index}"),
                    "template": null,
                    "ttl_seconds": 120
                }))
                .send()
                .await
        }
    };
    response
        .map(|response| response.status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

struct SandboxTtftSample {
    create_sandbox: Duration,
    queue_provision: Duration,
    provision_ready: Duration,
    queue_command: Duration,
    first_output: Duration,
    total: Duration,
}

struct SandboxTtftReport {
    samples: Vec<SandboxTtftSample>,
}

impl SandboxTtftReport {
    fn markdown(&self, name: &str) -> String {
        let total = self.summary(|sample| sample.total);
        let create_sandbox = self.summary(|sample| sample.create_sandbox);
        let queue_provision = self.summary(|sample| sample.queue_provision);
        let provision_ready = self.summary(|sample| sample.provision_ready);
        let queue_command = self.summary(|sample| sample.queue_command);
        let first_output = self.summary(|sample| sample.first_output);

        format!(
            "## {name}\n\n\
             Measurement: create sandbox request start -> first command output chunk observed. \
             Worker mode: Kubernetes dry-run; no cluster mutation. \
             Database: fresh temporary SQLite database.\n\n\
             | phase | samples | mean | p50 | p95 | p99 | min | max |\n\
             |---|---:|---:|---:|---:|---:|---:|---:|\n\
             {total_row}\
             {create_row}\
             {queue_provision_row}\
             {provision_ready_row}\
             {queue_command_row}\
             {first_output_row}",
            total_row = phase_row("total TTFT", &total),
            create_row = phase_row("create sandbox request", &create_sandbox),
            queue_provision_row = phase_row("queue provision job", &queue_provision),
            provision_ready_row = phase_row("provision job queued -> succeeded", &provision_ready),
            queue_command_row = phase_row("queue command request", &queue_command),
            first_output_row = phase_row("command queued -> first output", &first_output),
        )
    }

    fn summary(&self, phase: impl Fn(&SandboxTtftSample) -> Duration) -> BenchSummary {
        BenchSummary::from_durations(self.samples.iter().map(phase).collect(), 0)
    }
}

fn phase_row(name: &str, summary: &BenchSummary) -> String {
    format!(
        "| {name} | {count} | {mean} | {p50} | {p95} | {p99} | {min} | {max} |\n",
        count = summary.count,
        mean = format_duration(summary.mean),
        p50 = format_duration(summary.p50),
        p95 = format_duration(summary.p95),
        p99 = format_duration(summary.p99),
        min = format_duration(summary.min),
        max = format_duration(summary.max),
    )
}

struct BenchSummary {
    count: usize,
    failures: usize,
    elapsed: Duration,
    mean: Duration,
    p50: Duration,
    p95: Duration,
    p99: Duration,
    min: Duration,
    max: Duration,
}

impl BenchSummary {
    fn from_durations(mut durations: Vec<Duration>, failures: usize) -> Self {
        durations.sort_unstable();
        let elapsed: Duration = durations.iter().copied().sum();
        let count = durations.len();
        let mean = if count == 0 {
            Duration::ZERO
        } else {
            elapsed / count as u32
        };
        Self {
            count,
            failures,
            elapsed,
            mean,
            p50: percentile(&durations, 50),
            p95: percentile(&durations, 95),
            p99: percentile(&durations, 99),
            min: durations.first().copied().unwrap_or_default(),
            max: durations.last().copied().unwrap_or_default(),
        }
    }

    fn rps(&self) -> f64 {
        if self.elapsed.is_zero() {
            return 0.0;
        }
        self.count as f64 / self.elapsed.as_secs_f64()
    }

    fn markdown(&self, name: &str) -> String {
        format!(
            "## {name}\n\n| requests | failures | rps | mean | p50 | p95 | p99 | min | max |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n| {count} | {failures} | {rps:.1} | {mean} | {p50} | {p95} | {p99} | {min} | {max} |\n",
            count = self.count,
            failures = self.failures,
            rps = self.rps(),
            mean = format_duration(self.mean),
            p50 = format_duration(self.p50),
            p95 = format_duration(self.p95),
            p99 = format_duration(self.p99),
            min = format_duration(self.min),
            max = format_duration(self.max),
        )
    }
}

fn percentile(durations: &[Duration], percentile: usize) -> Duration {
    if durations.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((durations.len() - 1) * percentile).div_ceil(100);
    durations[rank]
}

fn format_duration(duration: Duration) -> String {
    let millis = duration.as_secs_f64() * 1000.0;
    format!("{millis:.2}ms")
}

async fn seed_database(options: &SeedOptions) -> anyhow::Result<()> {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect(&options.database_url)
        .await?;
    seed_workers(&pool, options).await?;
    seed_sandboxes(&pool, options).await?;
    seed_jobs(&pool, options).await?;
    Ok(())
}

async fn seed_workers(pool: &AnyPool, options: &SeedOptions) -> anyhow::Result<()> {
    let sql = format!(
        "insert into workers
         (id, tenant_id, name, status, provider, capabilities, max_concurrent_jobs, labels, registered_at, last_heartbeat_at)
         values ({})",
        placeholders(&options.database_url, 10)
    );
    let now = Utc::now().to_rfc3339();
    for index in 0..options.workers {
        sqlx::query(&sql)
            .bind(Uuid::now_v7().to_string())
            .bind("default")
            .bind(format!("bench-worker-{index}"))
            .bind(if index % 2 == 0 {
                "online"
            } else {
                "registered"
            })
            .bind("kubernetes")
            .bind(r#"["run_command","provision_sandbox","k8s_pod"]"#)
            .bind(4_i64)
            .bind(r#"{"cluster":"k3s-bench"}"#)
            .bind(&now)
            .bind(Some(now.clone()))
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn seed_sandboxes(pool: &AnyPool, options: &SeedOptions) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    let sandbox_sql = format!(
        "insert into sandboxes
         (id, tenant_id, name, state, template, created_at, updated_at, ttl_seconds, parent_snapshot_id)
         values ({})",
        placeholders(&options.database_url, 9)
    );
    let event_sql = format!(
        "insert into sandbox_events (id, sandbox_id, kind, data, created_at)
         values ({})",
        placeholders(&options.database_url, 5)
    );
    let command_sql = format!(
        "insert into commands
         (id, sandbox_id, status, argv, cwd, exit_code, stdout, stderr, created_at, finished_at)
         values ({})",
        placeholders(&options.database_url, 10)
    );
    let resource_sql = format!(
        "insert into runtime_resources
         (id, sandbox_id, snapshot_id, provider, resource_kind, purpose, resource_name, namespace,
          status, cluster, storage_class, snapshot_class, storage_size, runtime_image, service_port,
          target_port, source_snapshot_id, created_at, updated_at, ready_at, deleted_at, error)
         values ({})",
        placeholders(&options.database_url, 22)
    );

    for sandbox_index in 0..options.sandboxes {
        let sandbox_id = Uuid::now_v7().to_string();
        sqlx::query(&sandbox_sql)
            .bind(&sandbox_id)
            .bind("default")
            .bind(format!("bench-sandbox-{sandbox_index}"))
            .bind("ready")
            .bind("ubuntu-dev")
            .bind(&now)
            .bind(&now)
            .bind(3600_i64)
            .bind(Option::<String>::None)
            .execute(pool)
            .await?;

        for event_index in 0..options.events_per_sandbox {
            sqlx::query(&event_sql)
                .bind(Uuid::now_v7().to_string())
                .bind(&sandbox_id)
                .bind("lifecycle_changed")
                .bind(format!(r#"{{"seedEvent":{event_index}}}"#))
                .bind(&now)
                .execute(pool)
                .await?;
        }

        for command_index in 0..options.commands_per_sandbox {
            sqlx::query(&command_sql)
                .bind(Uuid::now_v7().to_string())
                .bind(&sandbox_id)
                .bind("finished")
                .bind(r#"["echo","bench"]"#)
                .bind(Option::<String>::None)
                .bind(0_i64)
                .bind("bench\n")
                .bind("")
                .bind(&now)
                .bind(Some(now.clone()))
                .execute(pool)
                .await?;

            if command_index == 0 {
                seed_runtime_resources(
                    pool,
                    options,
                    &resource_sql,
                    &sandbox_id,
                    sandbox_index,
                    &now,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn seed_runtime_resources(
    pool: &AnyPool,
    options: &SeedOptions,
    resource_sql: &str,
    sandbox_id: &str,
    sandbox_index: usize,
    now: &str,
) -> anyhow::Result<()> {
    for resource_index in 0..options.runtime_resources_per_sandbox {
        let (kind, purpose, service_port, target_port) = match resource_index % 4 {
            0 => ("pod", "runtime", None, None),
            1 => ("persistent_volume_claim", "workspace", None, None),
            2 => ("service", "ssh", Some(22_i64), Some("ssh".to_string())),
            _ => (
                "service",
                "desktop",
                Some(6080_i64),
                Some("desktop".to_string()),
            ),
        };
        sqlx::query(resource_sql)
            .bind(Uuid::now_v7().to_string())
            .bind(sandbox_id)
            .bind(Option::<String>::None)
            .bind("kubernetes")
            .bind(kind)
            .bind(purpose)
            .bind(format!("bench-{sandbox_index}-{resource_index}"))
            .bind("sandboxwich")
            .bind("ready")
            .bind(Some("k3s-bench"))
            .bind(Some("local-path"))
            .bind(Option::<String>::None)
            .bind(Some("2Gi"))
            .bind(Some("ghcr.io/evalops/sandboxwich-ubuntu-dev:latest"))
            .bind(service_port)
            .bind(target_port)
            .bind(Option::<String>::None)
            .bind(now)
            .bind(now)
            .bind(Some(now.to_string()))
            .bind(Option::<String>::None)
            .bind(Option::<String>::None)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn seed_jobs(pool: &AnyPool, options: &SeedOptions) -> anyhow::Result<()> {
    let sql = format!(
        "insert into jobs
         (id, tenant_id, kind, status, payload, required_capability, priority, attempts, max_attempts,
          scheduled_at, created_at, updated_at, last_error)
         values ({})",
        placeholders(&options.database_url, 13)
    );
    let now = Utc::now().to_rfc3339();
    for index in 0..options.jobs {
        sqlx::query(&sql)
            .bind(Uuid::now_v7().to_string())
            .bind("default")
            .bind("run_command")
            .bind(if index % 3 == 0 {
                "queued"
            } else {
                "succeeded"
            })
            .bind(r#"{"seed":"benchmark"}"#)
            .bind("run_command")
            .bind((index % 10) as i64)
            .bind(0_i64)
            .bind(3_i64)
            .bind(&now)
            .bind(&now)
            .bind(&now)
            .bind(Option::<String>::None)
            .execute(pool)
            .await?;
    }
    Ok(())
}

fn placeholders(database_url: &str, count: usize) -> String {
    (1..=count)
        .map(|index| {
            if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
                format!("${index}")
            } else {
                "?".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_ttft_command_parses_worker_options() {
        let args = Args::parse(vec![
            "sandbox-ttft".to_string(),
            "--api-bin".to_string(),
            "target/test-api".to_string(),
            "--worker-bin".to_string(),
            "target/test-worker".to_string(),
            "--runs".to_string(),
            "3".to_string(),
            "--poll-interval-ms".to_string(),
            "7".to_string(),
            "--timeout-ms".to_string(),
            "1234".to_string(),
        ])
        .expect("sandbox-ttft args should parse");

        let BenchCommand::SandboxTtft(options) = args.command else {
            panic!("expected sandbox-ttft command");
        };
        assert_eq!(options.api_bin, PathBuf::from("target/test-api"));
        assert_eq!(options.worker_bin, PathBuf::from("target/test-worker"));
        assert_eq!(options.runs, 3);
        assert_eq!(options.poll_interval, Duration::from_millis(7));
        assert_eq!(options.timeout, Duration::from_millis(1234));
    }

    #[test]
    fn sandbox_ttft_report_renders_phase_table() {
        let report = SandboxTtftReport {
            samples: vec![
                SandboxTtftSample {
                    create_sandbox: Duration::from_millis(1),
                    queue_provision: Duration::from_millis(2),
                    provision_ready: Duration::from_millis(3),
                    queue_command: Duration::from_millis(4),
                    first_output: Duration::from_millis(5),
                    total: Duration::from_millis(15),
                },
                SandboxTtftSample {
                    create_sandbox: Duration::from_millis(2),
                    queue_provision: Duration::from_millis(3),
                    provision_ready: Duration::from_millis(4),
                    queue_command: Duration::from_millis(5),
                    first_output: Duration::from_millis(6),
                    total: Duration::from_millis(20),
                },
            ],
        };

        let markdown = report.markdown("Sandbox TTFT");
        assert!(markdown.contains("create sandbox request start"));
        assert!(markdown.contains("| total TTFT | 2 |"));
        assert!(markdown.contains("| provision job queued -> succeeded | 2 |"));
        assert!(markdown.contains("| command queued -> first output | 2 |"));
        assert!(markdown.contains("20.00ms"));
    }
}
