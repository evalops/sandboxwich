use std::{
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
    Seed(SeedOptions),
}

#[derive(Clone)]
struct AllOptions {
    api_bin: PathBuf,
    runs: usize,
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
                runs: parser.usize_opt("--runs", 5)?,
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
                    "usage: sandboxwich-bench [all|startup|http|seed]\n\
                     examples:\n\
                       sandboxwich-bench all --api-bin target/debug/sandboxwich-api\n\
                       sandboxwich-bench startup --database-url sqlite:///tmp/bench.db\n\
                       sandboxwich-bench http --api-url http://127.0.0.1:3217 --path /readyz\n\
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
    let _ = std::fs::remove_file(db_path);

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
}

impl ApiProcess {
    async fn start(
        api_bin: &PathBuf,
        database_url: &str,
        auto_migrate: bool,
    ) -> anyhow::Result<Self> {
        let addr = free_addr()?;
        let mut child = Command::new(api_bin)
            .env("SANDBOXWICH_DATABASE_URL", database_url)
            .env("SANDBOXWICH_BIND", addr.to_string())
            .env(
                "SANDBOXWICH_AUTO_MIGRATE",
                if auto_migrate { "true" } else { "false" },
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start {}", api_bin.display()))?;

        let base_url = format!("http://{addr}");
        wait_for_health(&base_url, &mut child).await?;
        Ok(Self { child, base_url })
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ApiProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn wait_for_health(base_url: &str, child: &mut Child) -> anyhow::Result<()> {
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
            bail!("api exited before becoming healthy: {status}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    bail!("api did not become healthy");
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
