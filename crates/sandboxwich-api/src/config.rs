use anyhow::Context;
use std::net::SocketAddr;

#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub(crate) shared_token: Option<String>,
    pub(crate) tenant_tokens: Vec<TenantToken>,
    /// Distinct from `shared_token`/`tenant_tokens`: gates operator-only routes
    /// (currently `/snapshots/cleanup`) that act across tenant boundaries.
    pub(crate) operator_token: Option<String>,
    /// Explicit, off-by-default opt-out that lets the API serve with no
    /// authentication configured, trusting the `x-sandboxwich-tenant` header.
    /// Intended only for local development and benchmark harnesses.
    pub(crate) allow_insecure_no_auth: bool,
}

#[derive(Clone)]
pub(crate) struct TenantToken {
    pub(crate) tenant_id: String,
    pub(crate) token: String,
}

pub(crate) enum ApiCommand {
    Serve,
    Migrate,
    CheckSchema,
    OpenApi,
}

pub(crate) struct ApiConfig {
    pub(crate) command: ApiCommand,
    pub(crate) database_url: String,
    pub(crate) bind: SocketAddr,
    pub(crate) database_max_connections: u32,
    pub(crate) auto_migrate: bool,
    pub(crate) shared_token: Option<String>,
    pub(crate) tenant_tokens: Vec<TenantToken>,
    pub(crate) operator_token: Option<String>,
    pub(crate) allow_insecure_no_auth: bool,
    pub(crate) default_tenant_id: String,
    pub(crate) sweep_interval_ms: u64,
    pub(crate) disable_expiry_sweeper: bool,
}

pub(crate) fn load_api_config() -> anyhow::Result<ApiConfig> {
    let command = parse_api_command(std::env::args().skip(1))?;
    let bind = std::env::var("SANDBOXWICH_BIND").unwrap_or_else(|_| "127.0.0.1:3217".to_string());
    let bind: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid SANDBOXWICH_BIND value: {bind}"))?;

    let database_url = std::env::var("SANDBOXWICH_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://sandboxwich.db".to_string());
    let database_max_connections = parse_env_u32("SANDBOXWICH_DATABASE_MAX_CONNECTIONS", 5)?.max(1);
    let auto_migrate = parse_env_bool("SANDBOXWICH_AUTO_MIGRATE", true)?;
    let shared_token = std::env::var("SANDBOXWICH_API_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    let tenant_tokens =
        parse_tenant_tokens(std::env::var("SANDBOXWICH_TENANT_TOKENS").ok().as_deref())?;
    let operator_token = std::env::var("SANDBOXWICH_OPERATOR_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    let allow_insecure_no_auth = parse_env_bool("SANDBOXWICH_ALLOW_INSECURE_NO_AUTH", false)?;
    let default_tenant_id = std::env::var("SANDBOXWICH_DEFAULT_TENANT")
        .ok()
        .filter(|tenant| !tenant.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());
    let sweep_interval_ms = u64::from(parse_env_u32("SANDBOXWICH_SWEEP_INTERVAL_MS", 1000)?.max(1));
    let disable_expiry_sweeper = parse_env_bool("SANDBOXWICH_DISABLE_EXPIRY_SWEEPER", false)?;

    Ok(ApiConfig {
        command,
        database_url,
        bind,
        database_max_connections,
        auto_migrate,
        shared_token,
        tenant_tokens,
        operator_token,
        allow_insecure_no_auth,
        default_tenant_id,
        sweep_interval_ms,
        disable_expiry_sweeper,
    })
}

pub(crate) fn parse_api_command(
    args: impl IntoIterator<Item = String>,
) -> anyhow::Result<ApiCommand> {
    let mut args = args.into_iter();
    let command = match args.next().as_deref() {
        None | Some("serve") => ApiCommand::Serve,
        Some("migrate") => ApiCommand::Migrate,
        Some("check-schema") => ApiCommand::CheckSchema,
        Some("openapi") => ApiCommand::OpenApi,
        Some("--help") | Some("-h") => {
            println!("usage: sandboxwich-api [serve|migrate|check-schema|openapi]");
            std::process::exit(0);
        }
        Some(command) => anyhow::bail!(
            "unknown sandboxwich-api command {command:?}; expected serve, migrate, check-schema, or openapi"
        ),
    };
    if let Some(extra) = args.next() {
        anyhow::bail!("unexpected extra sandboxwich-api argument {extra:?}");
    }
    Ok(command)
}

pub(crate) fn parse_env_u32(name: &'static str, default: u32) -> anyhow::Result<u32> {
    let Some(value) = std::env::var(name).ok() else {
        return Ok(default);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(default);
    }
    value
        .parse()
        .with_context(|| format!("invalid {name} value: {value}"))
}

pub(crate) fn parse_env_bool(name: &'static str, default: bool) -> anyhow::Result<bool> {
    let Some(value) = std::env::var(name).ok() else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        value => anyhow::bail!("invalid {name} value: {value}"),
    }
}

pub(crate) fn parse_tenant_tokens(value: Option<&str>) -> anyhow::Result<Vec<TenantToken>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (tenant_id, token) = entry
                .split_once('=')
                .with_context(|| format!("invalid SANDBOXWICH_TENANT_TOKENS entry: {entry}"))?;
            let tenant_id = tenant_id.trim();
            let token = token.trim();
            if tenant_id.is_empty() || token.is_empty() {
                anyhow::bail!("invalid SANDBOXWICH_TENANT_TOKENS entry: {entry}");
            }
            Ok(TenantToken {
                tenant_id: tenant_id.to_string(),
                token: token.to_string(),
            })
        })
        .collect()
}
