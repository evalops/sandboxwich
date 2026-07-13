use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, lookup_host},
    time::timeout,
};

pub(crate) const DEFAULT_GATEWAY_DENY_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressGatewayPolicy {
    pub policy_id: String,
    pub hosts: Vec<String>,
    pub ports: Vec<u16>,
    pub denied_cidrs: Vec<IpNet>,
    #[serde(default = "default_connection_lifetime_seconds")]
    pub connection_lifetime_seconds: u64,
}

fn default_connection_lifetime_seconds() -> u64 {
    300
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedTarget {
    pub host: String,
    pub address: SocketAddr,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct GatewayDeny {
    reason_code: &'static str,
}

impl GatewayDeny {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    pub(crate) fn reason_code(&self) -> &'static str {
        self.reason_code
    }
}

impl std::fmt::Display for GatewayDeny {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for GatewayDeny {}

impl EgressGatewayPolicy {
    pub(crate) fn new(
        hosts: Vec<String>,
        ports: Vec<u16>,
        additional_denied_cidrs: impl IntoIterator<Item = IpNet>,
    ) -> anyhow::Result<Self> {
        let hosts = hosts
            .into_iter()
            .map(|host| normalize_rule(&host))
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .collect::<Vec<_>>();
        let ports = ports
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if hosts.is_empty() || ports.is_empty() {
            bail!("gateway policy requires at least one host and port");
        }
        let denied_cidrs = DEFAULT_GATEWAY_DENY_CIDRS
            .iter()
            .map(|cidr| cidr.parse::<IpNet>())
            .collect::<Result<BTreeSet<_>, _>>()?
            .into_iter()
            .chain(additional_denied_cidrs)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let identity_input = serde_json::to_vec(&(&hosts, &ports, &denied_cidrs))?;
        let policy_id = hex_digest(&identity_input);
        Ok(Self {
            policy_id,
            hosts,
            ports,
            denied_cidrs,
            connection_lifetime_seconds: default_connection_lifetime_seconds(),
        })
    }

    pub(crate) fn allows_host(&self, host: &str) -> bool {
        let host = normalize_host(host);
        self.hosts.iter().any(|rule| {
            if let Some(suffix) = rule.strip_prefix("*.") {
                host.strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
            } else {
                host == *rule
            }
        })
    }
}

fn normalize_rule(rule: &str) -> anyhow::Result<String> {
    let rule = normalize_host(rule);
    if rule.is_empty()
        || rule == "*"
        || rule.matches('*').count() > usize::from(rule.starts_with("*."))
        || (rule.contains('*') && !rule.starts_with("*."))
        || rule
            .strip_prefix("*.")
            .is_some_and(|base| !base.contains('.'))
    {
        bail!("invalid gateway host rule {rule}");
    }
    Ok(rule)
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn evaluate_target(
    policy: &EgressGatewayPolicy,
    host: &str,
    port: u16,
    addresses: impl IntoIterator<Item = IpAddr>,
) -> Result<ResolvedTarget, GatewayDeny> {
    if host.parse::<IpAddr>().is_ok() {
        return Err(GatewayDeny::new("direct_ip_denied"));
    }
    let host = normalize_host(host);
    if !policy.allows_host(&host) {
        return Err(GatewayDeny::new("host_not_allowed"));
    }
    if !policy.ports.contains(&port) {
        return Err(GatewayDeny::new("port_not_allowed"));
    }
    let addresses = addresses.into_iter().collect::<BTreeSet<_>>();
    if addresses.is_empty() {
        return Err(GatewayDeny::new("dns_empty"));
    }
    if addresses
        .iter()
        .any(|address| address_is_denied(*address, &policy.denied_cidrs))
    {
        return Err(GatewayDeny::new("protected_dns_answer"));
    }
    let address = *addresses.iter().next().expect("nonempty checked above");
    Ok(ResolvedTarget {
        host,
        address: SocketAddr::new(address, port),
    })
}

fn address_is_denied(address: IpAddr, denied_cidrs: &[IpNet]) -> bool {
    denied_cidrs.iter().any(|cidr| cidr.contains(&address))
        || match address {
            IpAddr::V6(address) => address.to_ipv4_mapped().is_some_and(|mapped| {
                denied_cidrs
                    .iter()
                    .any(|cidr| cidr.contains(&IpAddr::V4(mapped)))
            }),
            IpAddr::V4(_) => false,
        }
}

pub(crate) async fn run_egress_gateway(
    bind: SocketAddr,
    policy: EgressGatewayPolicy,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .context("bind egress gateway")?;
    loop {
        let (client, _) = listener.accept().await.context("accept gateway client")?;
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_client(client, &policy).await {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "policy_id": policy.policy_id,
                        "decision": "error",
                        "reason_code": "proxy_io_error",
                        "detail": error.to_string(),
                    })
                );
            }
        });
    }
}

async fn handle_client(mut client: TcpStream, policy: &EgressGatewayPolicy) -> anyhow::Result<()> {
    let header = match timeout(HEADER_TIMEOUT, read_header(&mut client)).await {
        Ok(Ok(header)) => header,
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => {
            write_response(&mut client, 408, "Request Timeout").await?;
            bail!("request_header_timeout");
        }
    };
    let request = match ProxyRequest::parse(&header) {
        Ok(request) => request,
        Err(reason) => {
            audit(policy, "", 0, "deny", reason.reason_code());
            write_response(&mut client, 400, "Bad Request").await?;
            return Ok(());
        }
    };
    let resolved = match resolve_target(policy, &request.host, request.port).await {
        Ok(target) => target,
        Err(reason) => {
            audit(
                policy,
                &request.host,
                request.port,
                "deny",
                reason.reason_code(),
            );
            write_response(&mut client, 403, "Forbidden").await?;
            return Ok(());
        }
    };
    let mut upstream = match TcpStream::connect(resolved.address).await {
        Ok(stream) => stream,
        Err(error) => {
            audit(
                policy,
                &request.host,
                request.port,
                "error",
                "connect_failed",
            );
            write_response(&mut client, 502, "Bad Gateway").await?;
            return Err(error.into());
        }
    };
    audit(
        policy,
        &request.host,
        request.port,
        "allow",
        "policy_allowed",
    );
    if request.connect {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        upstream.write_all(&request.forward_header).await?;
    }
    let lifetime = Duration::from_secs(policy.connection_lifetime_seconds.min(300));
    let _ = timeout(
        lifetime,
        tokio::io::copy_bidirectional(&mut client, &mut upstream),
    )
    .await;
    Ok(())
}

async fn resolve_target(
    policy: &EgressGatewayPolicy,
    host: &str,
    port: u16,
) -> Result<ResolvedTarget, GatewayDeny> {
    let addresses = lookup_host((host, port))
        .await
        .map_err(|_| GatewayDeny::new("dns_failed"))?
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    evaluate_target(policy, host, port, addresses)
}

async fn read_header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = Vec::with_capacity(1024);
    loop {
        if header.len() == MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request_header_too_large",
            ));
        }
        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request_header_eof",
            ));
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
}

#[derive(Debug)]
struct ProxyRequest {
    host: String,
    port: u16,
    connect: bool,
    forward_header: Vec<u8>,
}

impl ProxyRequest {
    fn parse(header: &[u8]) -> Result<Self, GatewayDeny> {
        let text = std::str::from_utf8(header).map_err(|_| GatewayDeny::new("invalid_header"))?;
        let first = text
            .lines()
            .next()
            .ok_or_else(|| GatewayDeny::new("invalid_header"))?;
        let mut fields = first.split_whitespace();
        let method = fields
            .next()
            .ok_or_else(|| GatewayDeny::new("invalid_header"))?;
        let target = fields
            .next()
            .ok_or_else(|| GatewayDeny::new("invalid_header"))?;
        let version = fields
            .next()
            .ok_or_else(|| GatewayDeny::new("invalid_header"))?;
        if fields.next().is_some() || !version.starts_with("HTTP/1.") {
            return Err(GatewayDeny::new("invalid_header"));
        }
        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = parse_authority(target, 443)?;
            return Ok(Self {
                host,
                port,
                connect: true,
                forward_header: Vec::new(),
            });
        }
        let rest = target
            .strip_prefix("http://")
            .ok_or_else(|| GatewayDeny::new("unsupported_proxy_request"))?;
        let (authority, path) = rest.split_once('/').map_or((rest, "/"), |(authority, _)| {
            (authority, &rest[authority.len()..])
        });
        let (host, port) = parse_authority(authority, 80)?;
        let forward_first = format!("{method} {path} {version}");
        let remainder = text.split_once("\r\n").map_or("\r\n", |(_, value)| value);
        Ok(Self {
            host,
            port,
            connect: false,
            forward_header: format!("{forward_first}\r\n{remainder}").into_bytes(),
        })
    }
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), GatewayDeny> {
    if authority.starts_with('[') || authority.contains('@') {
        return Err(GatewayDeny::new("invalid_authority"));
    }
    let (host, port) = authority.rsplit_once(':').map_or_else(
        || Ok((authority, default_port)),
        |(host, port)| {
            let port = port.parse().map_err(|_| GatewayDeny::new("invalid_port"))?;
            Ok((host, port))
        },
    )?;
    if host.is_empty() {
        return Err(GatewayDeny::new("invalid_authority"));
    }
    Ok((host.to_string(), port))
}

async fn write_response(stream: &mut TcpStream, status: u16, reason: &str) -> io::Result<()> {
    stream
        .write_all(
            format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .await
}

fn audit(policy: &EgressGatewayPolicy, host: &str, port: u16, decision: &str, reason: &str) {
    eprintln!(
        "{}",
        serde_json::json!({
            "policy_id": policy.policy_id,
            "host_hash": hex_digest(normalize_host(host).as_bytes()),
            "port": port,
            "decision": decision,
            "reason_code": reason,
        })
    );
}

fn hex_digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(hosts: &[&str]) -> EgressGatewayPolicy {
        EgressGatewayPolicy::new(
            hosts.iter().map(|host| (*host).to_string()).collect(),
            vec![80, 443],
            [],
        )
        .unwrap()
    }

    #[test]
    fn policy_accepts_exact_and_controlled_wildcard_hosts() {
        let policy = policy(&["api.example.com", "*.packages.example.com"]);
        assert!(policy.allows_host("api.example.com"));
        assert!(policy.allows_host("V1.PACKAGES.EXAMPLE.COM."));
        assert!(!policy.allows_host("packages.example.com"));
        assert!(!policy.allows_host("example.com"));
    }

    #[test]
    fn one_protected_dns_answer_denies_the_target() {
        let policy = policy(&["api.example.com"]);
        let result = evaluate_target(
            &policy,
            "api.example.com",
            443,
            [
                "203.0.113.10".parse().unwrap(),
                "169.254.169.254".parse().unwrap(),
            ],
        );
        assert_eq!(result.unwrap_err().reason_code(), "protected_dns_answer");
    }

    #[test]
    fn direct_ip_targets_are_denied_even_when_public() {
        let policy = policy(&["203.0.113.10"]);
        let result = evaluate_target(
            &policy,
            "203.0.113.10",
            443,
            ["203.0.113.10".parse().unwrap()],
        );
        assert_eq!(result.unwrap_err().reason_code(), "direct_ip_denied");
    }

    #[test]
    fn ipv4_mapped_private_answers_are_denied() {
        let policy = policy(&["api.example.com"]);
        let result = evaluate_target(
            &policy,
            "api.example.com",
            443,
            ["::ffff:169.254.169.254".parse().unwrap()],
        );
        assert_eq!(result.unwrap_err().reason_code(), "protected_dns_answer");
    }

    #[test]
    fn parser_rewrites_absolute_http_target_and_rejects_relative_form() {
        let request = ProxyRequest::parse(
            b"GET http://api.example.com/v1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(request.host, "api.example.com");
        assert_eq!(request.port, 80);
        assert!(request.forward_header.starts_with(b"GET /v1 HTTP/1.1\r\n"));
        assert_eq!(
            ProxyRequest::parse(b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
                .unwrap_err()
                .reason_code(),
            "unsupported_proxy_request"
        );
    }

    #[test]
    fn malformed_wildcards_are_rejected() {
        for host in ["*", "api.*.example.com", "**.example.com", "*.localhost"] {
            assert!(EgressGatewayPolicy::new(vec![host.to_string()], vec![443], []).is_err());
        }
    }

    #[tokio::test]
    async fn connect_tunnel_reaches_only_the_validated_socket() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let policy = EgressGatewayPolicy {
            policy_id: "test-policy".to_string(),
            hosts: vec!["localhost".to_string()],
            ports: vec![upstream_port],
            denied_cidrs: Vec::new(),
            connection_lifetime_seconds: 5,
        };
        let proxy_task = tokio::spawn(async move {
            let (server, _) = proxy.accept().await.unwrap();
            handle_client(server, &policy).await.unwrap();
        });

        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client
            .write_all(
                format!(
                    "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_header(&mut client).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        client.write_all(b"ping").await.unwrap();
        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        drop(client);

        upstream_task.await.unwrap();
        proxy_task.await.unwrap();
    }
}
