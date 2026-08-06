use crate::{
    config::IdentityMtlsConfig,
    handlers::resident_attestations::validate_maestro_workload_identity,
    health::{healthz, readyz},
    rejection_log::log_mutation_rejections,
    request_id::{attach_request_id, normalize_framework_errors},
    routes::DEFAULT_BODY_LIMIT_BYTES,
    state::AppState,
};
use anyhow::{Context, bail};
use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use rustls_pemfile::Item;
use std::{fs, io::Cursor, path::Path, sync::Arc};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

const MAX_IDENTITY_TLS_FILE_BYTES: u64 = 64 * 1024;

/// A capability marker that can only be installed by the dedicated Identity
/// listener. The handler intentionally does not accept a tenant principal.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IdentityServiceContext {
    _private: (),
}

#[derive(Debug)]
struct ExactUriClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    required_uri: Arc<str>,
}

impl ClientCertVerifier for ExactUriClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let (remainder, certificate) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !remainder.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::BadEncoding,
            ));
        }
        let has_exact_uri = certificate
            .subject_alternative_name()
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?
            .is_some_and(|extension| {
                extension.value.general_names.iter().any(
                    |name| matches!(name, GeneralName::URI(uri) if *uri == &*self.required_uri),
                )
            });
        if !has_exact_uri {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

fn read_bounded_pem(path: &Path, description: &str) -> anyhow::Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to inspect Identity mTLS {description}"))?;
    if !metadata.is_file() {
        bail!("Identity mTLS {description} is not a regular file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_IDENTITY_TLS_FILE_BYTES {
        bail!("Identity mTLS {description} must contain 1..={MAX_IDENTITY_TLS_FILE_BYTES} bytes");
    }
    let contents =
        fs::read(path).with_context(|| format!("failed to read Identity mTLS {description}"))?;
    if contents.is_empty()
        || u64::try_from(contents.len()).unwrap_or(u64::MAX) > MAX_IDENTITY_TLS_FILE_BYTES
    {
        bail!("Identity mTLS {description} must contain 1..={MAX_IDENTITY_TLS_FILE_BYTES} bytes");
    }
    Ok(contents)
}

fn certificate_chain(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let bytes = read_bounded_pem(path, "server certificate file")?;
    let mut certificates = Vec::new();
    for item in rustls_pemfile::read_all(&mut Cursor::new(bytes)) {
        match item.context("failed to parse Identity mTLS server certificate PEM")? {
            Item::X509Certificate(certificate) => certificates.push(certificate),
            _ => bail!("Identity mTLS server certificate file contains a non-certificate PEM"),
        }
    }
    if certificates.is_empty() {
        bail!("Identity mTLS server certificate file contains no certificates");
    }
    Ok(certificates)
}

fn private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let bytes = read_bounded_pem(path, "server private key file")?;
    let mut key = None;
    for item in rustls_pemfile::read_all(&mut Cursor::new(bytes)) {
        let parsed = match item.context("failed to parse Identity mTLS server private key PEM")? {
            Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
            Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
            Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
            _ => bail!("Identity mTLS server private key file contains a non-key PEM"),
        };
        if key.replace(parsed).is_some() {
            bail!("Identity mTLS server private key file must contain exactly one key");
        }
    }
    key.context("Identity mTLS server private key file contains no private key")
}

fn client_roots(path: &Path) -> anyhow::Result<RootCertStore> {
    let bytes = read_bounded_pem(path, "client CA file")?;
    let mut roots = RootCertStore::empty();
    let mut count = 0usize;
    for item in rustls_pemfile::read_all(&mut Cursor::new(bytes)) {
        match item.context("failed to parse Identity mTLS client CA PEM")? {
            Item::X509Certificate(certificate) => {
                roots
                    .add(certificate)
                    .context("Identity mTLS client CA file contains an invalid certificate")?;
                count += 1;
            }
            _ => bail!("Identity mTLS client CA file contains a non-certificate PEM"),
        }
    }
    if count == 0 {
        bail!("Identity mTLS client CA file contains no certificates");
    }
    Ok(roots)
}

pub(crate) fn identity_tls_config(config: &IdentityMtlsConfig) -> anyhow::Result<RustlsConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots(&config.client_ca_file)?),
        provider.clone(),
    )
    .build()
    .context("failed to build Identity mTLS client certificate verifier")?;
    let verifier = Arc::new(ExactUriClientCertVerifier {
        inner: verifier,
        required_uri: Arc::from(config.client_uri.as_str()),
    });
    let mut tls = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("failed to configure Identity mTLS protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            certificate_chain(&config.cert_file)?,
            private_key(&config.key_file)?,
        )
        .context("failed to configure Identity mTLS server certificate")?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(tls)))
}

pub(crate) fn identity_app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/healthz", get(healthz))
        .route("/v1/readyz", get(readyz))
        .route(
            "/v1/maestro-workload-identities/validate",
            post(validate_maestro_workload_identity),
        )
        .layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT_BYTES))
        .with_state(state)
        .layer(Extension(IdentityServiceContext { _private: () }))
        // The mTLS fence exposes one mutation route, and a rejection on it was
        // just as invisible as one on the tenant listener. There is no
        // `TenantContext` on this listener, so the log line reports an unknown
        // tenant; everything else (route template, status, code, latency) is
        // the same.
        .layer(middleware::from_fn(log_mutation_rejections))
        .layer(middleware::from_fn(normalize_framework_errors))
        .layer(middleware::from_fn(attach_request_id))
        .layer(middleware::from_fn(
            crate::lifecycle_contract::attach_lifecycle_contract,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::resident_attestations::IDENTITY_METRICS_TENANT_ID;
    use crate::{
        config::{
            AuthConfig, IDENTITY_SERVICE_CLIENT_URI, IdentityMtlsConfig, SandboxLifetimeConfig,
        },
        db::{connect_database, migrate_database},
        state::{ApexInstructionWaiters, AppState, ResidentBootstrapStore},
    };
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType, string::Ia5String,
    };
    use std::{fs, net::TcpListener, time::Duration};
    use tempfile::TempDir;

    struct TestPki {
        _directory: TempDir,
        config: IdentityMtlsConfig,
        server_ca_pem: String,
        exact_client_identity_pem: String,
        wrong_uri_client_identity_pem: String,
        untrusted_client_identity_pem: String,
    }

    fn certificate_authority() -> (Certificate, Issuer<'static, KeyPair>) {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        (certificate, Issuer::new(params, key))
    }

    fn signed_identity(
        issuer: &Issuer<'static, KeyPair>,
        uri: &str,
        usage: ExtendedKeyUsagePurpose,
    ) -> (String, String) {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri).unwrap())];
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, issuer).unwrap();
        (certificate.pem(), key.serialize_pem())
    }

    fn server_identity(issuer: &Issuer<'static, KeyPair>) -> (String, String) {
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let certificate = params.signed_by(&key, issuer).unwrap();
        (certificate.pem(), key.serialize_pem())
    }

    fn client_identity_pem(certificate: &str, key: &str) -> String {
        format!("{certificate}{key}")
    }

    fn test_pki() -> TestPki {
        let directory = tempfile::tempdir().unwrap();
        let (ca_certificate, ca_issuer) = certificate_authority();
        let ca_pem = ca_certificate.pem();
        let (server_certificate, server_key) = server_identity(&ca_issuer);
        let (exact_certificate, exact_key) = signed_identity(
            &ca_issuer,
            IDENTITY_SERVICE_CLIENT_URI,
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let (wrong_certificate, wrong_key) = signed_identity(
            &ca_issuer,
            "spiffe://identity.evalops.dev/service/other",
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let (_, untrusted_issuer) = certificate_authority();
        let (untrusted_certificate, untrusted_key) = signed_identity(
            &untrusted_issuer,
            IDENTITY_SERVICE_CLIENT_URI,
            ExtendedKeyUsagePurpose::ClientAuth,
        );
        let cert_file = directory.path().join("server.crt");
        let key_file = directory.path().join("server.key");
        let client_ca_file = directory.path().join("client-ca.crt");
        fs::write(&cert_file, server_certificate).unwrap();
        fs::write(&key_file, server_key).unwrap();
        fs::write(&client_ca_file, &ca_pem).unwrap();
        TestPki {
            _directory: directory,
            config: IdentityMtlsConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                cert_file,
                key_file,
                client_ca_file,
                client_uri: IDENTITY_SERVICE_CLIENT_URI.into(),
            },
            server_ca_pem: ca_pem,
            exact_client_identity_pem: client_identity_pem(&exact_certificate, &exact_key),
            wrong_uri_client_identity_pem: client_identity_pem(&wrong_certificate, &wrong_key),
            untrusted_client_identity_pem: client_identity_pem(
                &untrusted_certificate,
                &untrusted_key,
            ),
        }
    }

    async fn test_state() -> AppState {
        let database_path = std::env::temp_dir().join(format!(
            "sandboxwich-identity-mtls-{}.db",
            uuid::Uuid::now_v7()
        ));
        let db = connect_database(&format!("sqlite://{}", database_path.display()), 1)
            .await
            .unwrap();
        migrate_database(&db).await.unwrap();
        AppState {
            db,
            auth: AuthConfig {
                shared_token: None,
                tenant_tokens: vec![],
                operator_token: None,
                allow_insecure_no_auth: false,
            },
            default_tenant_id: "default".into(),
            apex_callback_base_url: None,
            placement_attestation_derivation_key: None,
            apex_waiters: ApexInstructionWaiters::default(),
            resident_bootstraps: ResidentBootstrapStore::default(),
            sandbox_lifetime: SandboxLifetimeConfig::default(),
            apex_callback_test_hook: None,
        }
    }

    fn client(ca_pem: &str, identity_pem: Option<&str>) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap());
        if let Some(identity_pem) = identity_pem {
            builder =
                builder.identity(reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap());
        }
        builder.build().unwrap()
    }

    #[tokio::test]
    async fn identity_listener_requires_the_trusted_exact_uri_and_has_no_general_routes() {
        let pki = test_pki();
        let tls = identity_tls_config(&pki.config).unwrap();
        let listener = TcpListener::bind(pki.config.bind).unwrap();
        let address = listener.local_addr().unwrap();
        let state = test_state().await;
        let metrics_db = state.db.clone();
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .handle(server_handle)
                .serve(identity_app(state).into_make_service())
                .await
                .unwrap();
        });
        handle.listening().await.expect("listener bound");
        let base_url = format!("https://localhost:{}", address.port());

        assert!(
            client(&pki.server_ca_pem, None)
                .get(format!("{base_url}/healthz"))
                .header(
                    "x-forwarded-client-cert",
                    format!("URI={IDENTITY_SERVICE_CLIENT_URI}"),
                )
                .header("x-client-spiffe-id", IDENTITY_SERVICE_CLIENT_URI)
                .send()
                .await
                .is_err(),
            "forwarded identity headers cannot replace a mandatory client certificate"
        );
        for rejected_identity in [
            &pki.wrong_uri_client_identity_pem,
            &pki.untrusted_client_identity_pem,
        ] {
            assert!(
                client(&pki.server_ca_pem, Some(rejected_identity))
                    .get(format!("{base_url}/healthz"))
                    .send()
                    .await
                    .is_err(),
                "the listener must reject an untrusted or wrong-URI client certificate"
            );
        }

        let accepted = client(&pki.server_ca_pem, Some(&pki.exact_client_identity_pem));
        assert_eq!(
            accepted
                .get(format!("{base_url}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(
            accepted
                .get(format!("{base_url}/v1/sandboxes"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NOT_FOUND
        );
        let fence = accepted
            .post(format!(
                "{base_url}/v1/maestro-workload-identities/validate"
            ))
            .json(&sandboxwich_core::ValidateMaestroWorkloadIdentityRequest {
                organization_id: "tenant-from-body".into(),
                workspace_id: "workspace-1".into(),
                sandbox_id: sandboxwich_core::SandboxId::new(),
                pod_uid: uuid::Uuid::now_v7(),
                generation: 1,
                runner_session_id: "runner-session-1".into(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(fence.status(), reqwest::StatusCode::NOT_FOUND);
        assert!(
            fence
                .text()
                .await
                .unwrap()
                .contains("placement_attestation_not_found"),
            "the exact fence route must be present on the mTLS listener"
        );
        let metric_count: i64 = sqlx::query_scalar(
            "select sample_count from maestro_activation_validation_metrics
             where tenant_id = ? and outcome = ? and reason = ?",
        )
        .bind(IDENTITY_METRICS_TENANT_ID)
        .bind("rejected")
        .bind("not_found")
        .fetch_one(&metrics_db.pool)
        .await
        .unwrap();
        assert_eq!(metric_count, 1);

        handle.graceful_shutdown(Some(Duration::from_secs(1)));
        server.await.unwrap();
    }

    #[test]
    fn identity_tls_pem_reads_are_bounded() {
        let pki = test_pki();
        fs::write(
            &pki.config.cert_file,
            vec![b'x'; usize::try_from(MAX_IDENTITY_TLS_FILE_BYTES).unwrap() + 1],
        )
        .unwrap();
        let error = identity_tls_config(&pki.config).unwrap_err();
        assert!(
            error.to_string().contains("1..=65536 bytes"),
            "unexpected error: {error}"
        );
    }
}
