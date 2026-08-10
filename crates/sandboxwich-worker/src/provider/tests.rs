use super::*;
use sandboxwich_core::{
    MAX_COMMAND_STDIN_BYTES, NetworkAllowRule, RuntimeResourceInventoryItem, SterileCellId,
    SterileCellReleaseTrustClassV1, SterileCellRuntimeClass, SterilePoolCandidateV1,
};
use sandboxwich_core::{SandboxSecretMount, SecretRef, SecretRefId, SecretRefState, SecretSource};

fn sterile_maestro_candidate(sandbox_id: SandboxId) -> SterilePoolCandidateV1 {
    SterilePoolCandidateV1 {
        cell_id: SterileCellId(sandbox_id.0),
        release: SterileCellReleaseTrustClassV1 {
            release_set_id: "release-test".into(),
            runtime_class: SterileCellRuntimeClass::KataMicrovm,
            policy_digest: "a".repeat(64),
            signature: "swrs1_test".into(),
        },
        agent_image: format!(
            "ghcr.io/evalops/sandboxwich-agent@sha256:{}",
            "b".repeat(64)
        ),
        maestro_image: format!("ghcr.io/evalops/maestro@sha256:{}", "c".repeat(64)),
        service_name: format!("sandboxwich-mc-{sandbox_id}"),
        pod_name: None,
        pod_uid: None,
    }
}

#[test]
fn compiler_cache_materialization_stages_then_restores_before_success() {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-cache-materialize-kubectl-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let script_path = dir.join("kubectl");
    let log_path = dir.join("log");
    let content = b"archive";
    let digest = sha256_hex(content);
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{log}"
case " $* " in
  *" get pod "*) printf '%s\n' 'pod/sandboxwich-test' ;;
  *" /usr/bin/sha256sum "*) printf '%s  %s\n' '{digest}' '{path}' ;;
  *" compiler-cache-restore "*) bytes=$(wc -c); printf 'restore-stdin-bytes=%s\n' "$bytes" >> "{log}" ;;
  *" exec "*) cat >/dev/null 2>&1 || true ;;
esac
"#,
        log = log_path.display(),
        path = MaterializeFileDestination::CompilerCacheArchive.guest_path(),
    );
    std::fs::write(&script_path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).unwrap();
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    provider
        .materialize_file(
            SandboxId::new(),
            MaterializeFileDestination::CompilerCacheArchive,
            &digest,
            content,
            Some(br#"{"schemaVersion":1}"#),
            &CancelSignal::never_cancelled(),
        )
        .unwrap();
    let log = std::fs::read_to_string(&log_path).unwrap();
    let stage = log.find(" compiler-cache-stage-archive ").unwrap();
    let restore_line = log
        .lines()
        .find(|line| line.contains(" compiler-cache-restore "))
        .expect("provider acknowledged success without activating the staged cache");
    let restore = log.find(restore_line).unwrap();
    assert!(stage < restore);
    assert!(log[stage..restore].contains(COMPILER_CACHE_HELPER_CONTAINER));
    assert!(restore_line.contains(COMPILER_CACHE_HELPER_CONTAINER));
    assert!(
        log.lines()
            .any(|line| line.starts_with("restore-stdin-bytes=") && line.ends_with("19"))
    );
    std::fs::remove_dir_all(dir).unwrap();
}

fn assert_compiler_cache_containers_are_restricted(pod: &serde_json::Value) {
    let init = &pod["spec"]["initContainers"][0];
    assert_eq!(init["name"], "compiler-cache-init");
    let containers = pod["spec"]["containers"].as_array().unwrap();
    let workload = containers
        .iter()
        .find(|container| container["name"] == "sandbox")
        .unwrap();
    let helper = containers
        .iter()
        .find(|container| container["name"] == COMPILER_CACHE_HELPER_CONTAINER)
        .unwrap();

    for (label, container) in [
        ("compiler-cache-init", init),
        ("compiler-cache-helper", helper),
    ] {
        let security = &container["securityContext"];
        // PodSecurity restricted:latest: non-root, no added capabilities, no
        // privilege escalation, RuntimeDefault seccomp.
        assert_eq!(security["runAsNonRoot"], true, "{label}");
        assert_eq!(security["runAsUser"], 10001, "{label}");
        assert_eq!(security["runAsGroup"], 10001, "{label}");
        assert_eq!(security["allowPrivilegeEscalation"], false, "{label}");
        assert_eq!(security["readOnlyRootFilesystem"], true, "{label}");
        assert_eq!(
            security["capabilities"],
            json!({"drop": ["ALL"]}),
            "{label}"
        );
        assert!(security["capabilities"].get("add").is_none(), "{label}");
        assert_eq!(
            security["seccompProfile"],
            json!({"type": "RuntimeDefault"}),
            "{label}"
        );

        let mounts = container["volumeMounts"].as_array().unwrap();
        assert!(
            mounts.iter().any(|mount| {
                mount["name"] == "compiler-cache-private"
                    && mount["mountPath"] == "/run/sandboxwich/compiler-cache"
            }),
            "{label} does not mount the private staging volume"
        );
        // The 5m/16Mi request shape is budgeted in the deploy repo's namespace
        // quota arithmetic; changing it needs a matching quota change.
        assert_eq!(
            container["resources"]["requests"],
            json!({"cpu": "5m", "memory": "16Mi"}),
            "{label}"
        );
    }

    // The guest never mounts the staging volume, so the staged restore archive
    // is outside the guest's mount namespace entirely.
    assert!(
        workload["volumeMounts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|mount| mount["name"] != "compiler-cache-private"),
        "the guest container mounts the compiler-cache staging volume"
    );
    let volumes = pod["spec"]["volumes"].as_array().unwrap();
    assert_eq!(volumes[0]["name"], "workspace");
    assert!(volumes.iter().any(|volume| {
        volume["name"] == "compiler-cache-private" && volume["emptyDir"].is_object()
    }));
}

#[test]
fn compiler_cache_containers_are_non_root_with_a_guest_invisible_staging_volume() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let pod = provider.pod_manifest(SandboxId::new(), &SandboxProvisionSpec::default());
    let init = &pod["spec"]["initContainers"][0];
    assert_eq!(
        init["command"],
        json!([
            "/usr/local/bin/sandboxwich-agent",
            "compiler-cache-prepare-workspace"
        ])
    );

    assert_compiler_cache_containers_are_restricted(&pod);

    let containers = pod["spec"]["containers"].as_array().unwrap();
    let workload = containers
        .iter()
        .find(|container| container["name"] == "sandbox")
        .unwrap();
    let helper = containers
        .iter()
        .find(|container| container["name"] == COMPILER_CACHE_HELPER_CONTAINER)
        .unwrap();
    assert_eq!(workload["securityContext"]["runAsNonRoot"], true);
    assert_eq!(pod["spec"]["securityContext"]["runAsUser"], 10001);
    assert_eq!(pod["spec"]["securityContext"]["runAsGroup"], 10001);
    assert!(helper.get("env").is_none());
    assert!(helper.get("ports").is_none());
    assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
}

#[test]
fn kubernetes_pod_marks_only_authoritative_sterile_pool_candidates() {
    let sandbox_id = SandboxId::new();
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let ordinary = provider.pod_manifest(sandbox_id, &SandboxProvisionSpec::default());
    let ordinary_env = ordinary["spec"]["containers"][0]["env"].as_array().unwrap();
    assert!(
        ordinary_env
            .iter()
            .all(|entry| { entry["name"] != "SANDBOXWICH_STERILE_POOL_CANDIDATE_V1" })
    );

    let candidate = sterile_maestro_candidate(sandbox_id);
    let spec = SandboxProvisionSpec {
        sterile_pool_candidate: Some(candidate.clone()),
        workspace_mode: WorkspaceMode::Persistent,
        tenant_id: Some("tenant-canary-must-not-render".to_string()),
        network_egress: NetworkEgress::AllowAll,
        ..SandboxProvisionSpec::default()
    };
    let apply = KubernetesApplyProvider::new(
        provider
            .clone()
            .with_runtime_class_name(Some("kata".to_string()))
            .with_guest_credentials(
                sandbox_id,
                Uuid::now_v7(),
                "http://sandboxwich-api.sandboxwich-ci.svc.cluster.local:3217",
                "sbw_gtok_candidate",
            ),
        "kubectl",
    );
    let manifests = apply
        .provision_manifests(sandbox_id, &spec)
        .expect("candidate manifests");
    let pool_pod = manifests
        .iter()
        .find(|manifest| {
            manifest["kind"] == "Pod"
                && manifest["metadata"]["name"] == format!("sandboxwich-{sandbox_id}")
        })
        .expect("tenant candidate Pod");
    let supervisor_pod = manifests
        .iter()
        .find(|manifest| {
            manifest["kind"] == "Pod"
                && manifest["metadata"]["name"] == format!("sandboxwich-supervisor-{sandbox_id}")
        })
        .expect("candidate supervisor Pod");
    let marker = pool_pod["spec"]["containers"][0]["env"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "SANDBOXWICH_STERILE_POOL_CANDIDATE_V1")
        .expect("pool candidate marker missing from sandbox container");
    let decoded: SterilePoolCandidateV1 =
        serde_json::from_str(marker["value"].as_str().unwrap()).unwrap();
    assert_eq!(decoded, candidate);

    assert_eq!(
        manifests
            .iter()
            .map(|manifest| manifest["kind"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "PersistentVolumeClaim",
            "Secret",
            "Secret",
            "Secret",
            "NetworkPolicy",
            "NetworkPolicy",
            "Service",
            "Pod",
            "Pod"
        ],
        "candidate provisioning separates tenant and supervisor security boundaries"
    );
    assert_eq!(
        pool_pod["spec"]["initContainers"][0]["image"],
        candidate.agent_image
    );
    assert_eq!(
        pool_pod["spec"]["containers"][0]["image"],
        candidate.maestro_image
    );
    assert_eq!(
        supervisor_pod["spec"]["containers"][0]["command"],
        json!(["/opt/sandboxwich/bin/sandboxwich-agent", "daemon"])
    );
    assert_eq!(
        pool_pod["spec"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == "bootstrap")
            .unwrap()["emptyDir"]["medium"],
        "Memory"
    );
    let rendered = serde_json::to_string(&manifests).unwrap();
    assert!(!rendered.contains("placement-attestation"));
    assert!(!rendered.contains("managed-gateway-token"));
    assert!(!rendered.contains("tenant-canary-must-not-render"));
    assert!(!rendered.contains("0.0.0.0/0"));
    assert!(!rendered.contains("sandboxwich-ssh"));
    assert!(!rendered.contains("sandboxwich-desktop"));
    assert!(pool_pod["spec"]["runtimeClassName"].is_string());
    assert!(supervisor_pod["spec"].get("runtimeClassName").is_none());
    assert_eq!(pool_pod["spec"]["containers"].as_array().unwrap().len(), 1);
    let maestro = &pool_pod["spec"]["containers"][0];
    let maestro_rendered = serde_json::to_string(maestro).unwrap();
    assert!(!maestro_rendered.contains("sandboxwich-guest-token"));
    assert!(!maestro_rendered.contains("SANDBOXWICH_API"));
    assert!(!maestro_rendered.contains("SANDBOXWICH_GUEST_TOKEN"));
    assert!(maestro_rendered.contains("SANDBOXWICH_STERILE_POOL_CANDIDATE_V1"));
    assert!(maestro_rendered.contains("SANDBOXWICH_PROVIDER_POD_NAME"));
    assert!(maestro_rendered.contains("SANDBOXWICH_PROVIDER_POD_UID"));
    assert!(maestro_rendered.contains("--activation-bind"));
    assert!(maestro_rendered.contains("0.0.0.0:9443"));
    assert!(maestro_rendered.contains("activation-tls"));
    let supervisor_rendered = serde_json::to_string(supervisor_pod).unwrap();
    assert!(supervisor_rendered.contains("SANDBOXWICH_GUEST_TOKEN_FILE"));
    assert!(supervisor_rendered.contains("SANDBOXWICH_STERILE_ACTIVATION_URL"));
    assert!(supervisor_rendered.contains(":9443"));
    assert!(!maestro_rendered.contains("SANDBOXWICH_GUEST_TOKEN"));
    assert!(!maestro_rendered.contains("SANDBOXWICH_API"));
    assert!(!supervisor_rendered.contains(MAESTRO_HOSTED_RUNNER_WORKSPACE_ROOT));
    assert!(!rendered.contains("\"name\":\"activation\",\"emptyDir\""));
    let policies = manifests
        .iter()
        .filter(|manifest| manifest["kind"] == "NetworkPolicy")
        .collect::<Vec<_>>();
    assert_eq!(policies.len(), 2);
    let policies_rendered = serde_json::to_string(&policies).unwrap();
    for required in [
        "sandboxwich-api",
        "identity",
        "llm-gateway",
        "runner-host",
        "9443",
    ] {
        assert!(
            policies_rendered.contains(required),
            "missing {required} policy boundary"
        );
    }
    let service = manifests
        .iter()
        .find(|manifest| manifest["kind"] == "Service")
        .unwrap();
    assert_eq!(service["metadata"]["name"], candidate.service_name);
    assert_eq!(service["spec"]["ports"][0]["port"], 8443);
    assert_eq!(service["spec"]["ports"][1]["port"], 9443);

    let tls_secrets = manifests
        .iter()
        .filter(|manifest| {
            manifest["kind"] == "Secret"
                && manifest["metadata"]["name"]
                    .as_str()
                    .is_some_and(|name| name.contains("activation"))
        })
        .collect::<Vec<_>>();
    assert_eq!(tls_secrets.len(), 2);
    assert!(manifests.iter().all(|manifest| {
        manifest["metadata"]["labels"]["sandboxwich.dev/sandbox-id"]
            == json!(sandbox_id.to_string())
    }));
    let teardown = apply.teardown_args(sandbox_id);
    assert!(teardown.contains(&SANDBOX_TEARDOWN_RESOURCE_KINDS.to_string()));
    assert!(SANDBOX_TEARDOWN_RESOURCE_KINDS.contains("pod"));
    assert!(SANDBOX_TEARDOWN_RESOURCE_KINDS.contains("persistentvolumeclaim"));
    assert!(SANDBOX_TEARDOWN_RESOURCE_KINDS.contains("service"));
    assert!(SANDBOX_TEARDOWN_RESOURCE_KINDS.contains("networkpolicy"));
    assert!(SANDBOX_TEARDOWN_RESOURCE_KINDS.contains("secret"));
    let metadata = apply
        .dry_run
        .metadata(sandbox_id, "provision", &spec)
        .expect("candidate metadata");
    let metadata_json = serde_json::to_string(&metadata).unwrap();
    for secret in tls_secrets {
        for value in secret["stringData"].as_object().unwrap().values() {
            let secret_value = value.as_str().unwrap();
            assert!(!metadata_json.contains(secret_value));
        }
    }
}

#[test]
fn sterile_maestro_candidate_rejects_unpinned_or_noncanonical_runtime_identity() {
    let sandbox_id = SandboxId::new();
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_runtime_class_name(Some("kata".to_string()))
            .with_guest_credentials(
                sandbox_id,
                Uuid::now_v7(),
                "http://sandboxwich-api.sandboxwich-ci.svc.cluster.local:3217",
                "sbw_gtok_candidate",
            ),
        "kubectl",
    );
    let mut candidate = sterile_maestro_candidate(sandbox_id);
    candidate.maestro_image = "ghcr.io/evalops/maestro:latest".to_string();
    let mut spec = SandboxProvisionSpec {
        workspace_mode: WorkspaceMode::Persistent,
        sterile_pool_candidate: Some(candidate),
        ..SandboxProvisionSpec::default()
    };
    assert!(
        provider
            .provision_manifests(sandbox_id, &spec)
            .expect_err("a mutable Maestro image must fail closed")
            .to_string()
            .contains("digest-pinned")
    );

    let mut candidate = sterile_maestro_candidate(sandbox_id);
    candidate.service_name = "attacker-selected-service".to_string();
    spec.sterile_pool_candidate = Some(candidate);
    assert!(
        provider
            .provision_manifests(sandbox_id, &spec)
            .expect_err("a noncanonical Service identity must fail closed")
            .to_string()
            .contains("service name is not canonical")
    );
}

#[test]
fn sterile_activation_tls_rejects_forged_identity_and_key_mismatch_without_leaking_keys() {
    let sandbox_id = SandboxId::new();
    let candidate = sterile_maestro_candidate(sandbox_id);
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let tls = provider
        .sterile_activation_tls(sandbox_id, &candidate)
        .expect("generate activation PKI");

    let mut forged = tls.server_secret.clone();
    forged["metadata"]["annotations"]["sandboxwich.dev/activation-server-dns"] =
        json!("attacker.invalid");
    let error = validate_activation_tls_secret(&forged)
        .expect_err("a forged semantic annotation must not authorize the certificate");
    assert!(error.to_string().contains("wrong identity"));

    let mut mismatched = tls.server_secret.clone();
    let private_key = tls.client_secret["stringData"]["client.key"]
        .as_str()
        .unwrap()
        .to_string();
    mismatched["stringData"]["tls.key"] = json!(private_key.clone());
    let error = validate_activation_tls_secret(&mismatched)
        .expect_err("a mismatched leaf private key must fail closed");
    let rendered_error = format!("{error:#}");
    assert!(rendered_error.contains("does not match"));
    assert!(!rendered_error.contains(&private_key));
}

#[test]
fn sterile_activation_tls_adopts_existing_ca_and_recovers_missing_server_secret() {
    let sandbox_id = SandboxId::new();
    let candidate = sterile_maestro_candidate(sandbox_id);
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let first = provider
        .sterile_activation_tls(sandbox_id, &candidate)
        .expect("initial activation PKI");
    let recovered = provider
        .sterile_activation_tls_from_existing_client(
            sandbox_id,
            &candidate,
            first.client_secret.clone(),
        )
        .expect("recover server identity from the fixed client PKI Secret");
    assert_eq!(
        recovered.client_secret["metadata"]["annotations"]["sandboxwich.dev/activation-ca-sha256"],
        recovered.server_secret["metadata"]["annotations"]["sandboxwich.dev/activation-ca-sha256"]
    );
    validate_activation_tls_secret(&recovered.client_secret).unwrap();
    validate_activation_tls_secret(&recovered.server_secret).unwrap();
    validate_adoption_contract(&recovered.client_secret, &first.client_secret)
        .expect("the fixed client Secret is adopted without random-secret drift");
    validate_adoption_contract(&recovered.server_secret, &first.server_secret)
        .expect("a regenerated server leaf under the adopted CA matches semantically");

    let unrelated = provider
        .sterile_activation_tls(sandbox_id, &candidate)
        .expect("unrelated activation PKI");
    let error = validate_adoption_contract(&recovered.server_secret, &unrelated.server_secret)
        .expect_err("a server Secret from another CA must fail closed");
    assert!(error.to_string().contains("does not match"));
}

#[test]
fn apex_trusted_supervisor_does_not_leak_root_into_the_compiler_cache_containers() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
        ..SandboxProvisionSpec::default()
    };
    let pod = provider.pod_manifest(SandboxId::new(), &spec);
    // The trusted profile deliberately runs the pod and the guest container as
    // root; the compiler-cache containers must not inherit that.
    assert_eq!(pod["spec"]["securityContext"]["runAsUser"], 0);
    assert_compiler_cache_containers_are_restricted(&pod);
}

#[test]
fn only_compiler_cache_provider_operations_can_target_compiler_cache_helper() {
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None),
        "kubectl",
    );
    let sandbox_id = SandboxId::new();
    let request = AgentCommandRequest {
        argv: vec!["true".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
        timeout_secs: None,
    };
    let generic = provider.exec_args(sandbox_id, &request);
    assert!(!generic.iter().any(|arg| arg == "-c"));
    let cache = provider.exec_args_in_container(
        sandbox_id,
        &request,
        Some(COMPILER_CACHE_HELPER_CONTAINER),
    );
    assert!(cache.windows(2).any(|args| {
        args == [
            "-c".to_string(),
            COMPILER_CACHE_HELPER_CONTAINER.to_string(),
        ]
    }));
    let normal = provider.exec_args_in_container(sandbox_id, &request, None);
    assert!(
        !normal
            .iter()
            .any(|arg| arg == COMPILER_CACHE_HELPER_CONTAINER)
    );
    assert_eq!(
        KubernetesApplyProvider::materialize_container(
            &MaterializeFileDestination::CompilerCacheArchive
        ),
        Some(COMPILER_CACHE_HELPER_CONTAINER)
    );
    for destination in [
        MaterializeFileDestination::ApexWorld,
        MaterializeFileDestination::ApexTask,
        MaterializeFileDestination::ApexTaskInstructions,
        MaterializeFileDestination::ApexGradingBundle,
    ] {
        assert_eq!(
            KubernetesApplyProvider::materialize_container(&destination),
            None
        );
    }
}

fn isolated_sidecar_spec(bootstrap: &[u8]) -> IsolatedResidentProcessSpec {
    IsolatedResidentProcessSpec {
        process_name: sandboxwich_core::ORB_SIDECAR_RESIDENT_PROCESS_NAME.to_string(),
        sandbox_id: SandboxId::new(),
        process_id: sandboxwich_core::ResidentProcessId::new(),
        generation: 7,
        lease_id: Uuid::now_v7(),
        argv: vec!["/opt/orb/bin/orb-sidecar".to_string()],
        cwd: Some("/workspace".to_string()),
        env: BTreeMap::from([("ORB_API".to_string(), "https://orb.invalid".to_string())]),
        workspace_mode: WorkspaceMode::Persistent,
        workspace_claim_name: None,
        bootstrap: Some(IsolatedResidentProcessBootstrap {
            content: bootstrap.to_vec(),
            target_file: "/run/sandboxwich/bootstrap/orb-token".to_string(),
            mode: 0o400,
            placement_attestation: None,
        }),
    }
}

fn maestro_hosted_runner_spec() -> IsolatedResidentProcessSpec {
    let sandbox_id = SandboxId::new();
    IsolatedResidentProcessSpec {
        process_name: sandboxwich_core::MAESTRO_HOSTED_RUNNER_RESIDENT_PROCESS_NAME.to_string(),
        sandbox_id,
        process_id: sandboxwich_core::ResidentProcessId::new(),
        generation: 4,
        lease_id: Uuid::now_v7(),
        argv: vec![
            "/usr/local/bin/maestro".to_string(),
            "hosted-runner".to_string(),
            "--listen".to_string(),
            "0.0.0.0:8443".to_string(),
        ],
        cwd: Some(sandboxwich_core::MAESTRO_HOSTED_RUNNER_WORKSPACE_ROOT.to_string()),
        workspace_mode: WorkspaceMode::Persistent,
        workspace_claim_name: Some(format!("sandboxwich-pvc-{sandbox_id}")),
        env: BTreeMap::from([
            (
                "MAESTRO_KUBERNETES_TOKEN_FILE".to_string(),
                sandboxwich_core::MAESTRO_HOSTED_RUNNER_TOKEN_FILE.to_string(),
            ),
            (
                "MAESTRO_IDENTITY_EXCHANGE_URL".to_string(),
                sandboxwich_core::MAESTRO_HOSTED_RUNNER_IDENTITY_EXCHANGE_URL.to_string(),
            ),
            (
                "MAESTRO_IDENTITY_TLS_CA_FILE".to_string(),
                sandboxwich_core::MAESTRO_HOSTED_RUNNER_IDENTITY_CA_FILE.to_string(),
            ),
            (
                "MAESTRO_WORKSPACE_ROOT".to_string(),
                sandboxwich_core::MAESTRO_HOSTED_RUNNER_WORKSPACE_ROOT.to_string(),
            ),
            ("MAESTRO_ORGANIZATION_ID".to_string(), "org-1".to_string()),
            (
                "MAESTRO_WORKSPACE_ID".to_string(),
                "workspace-1".to_string(),
            ),
            ("MAESTRO_SANDBOX_ID".to_string(), sandbox_id.to_string()),
            ("MAESTRO_PLACEMENT_GENERATION".to_string(), "7".to_string()),
            (
                "MAESTRO_RUNNER_SESSION_ID".to_string(),
                "runner-session-1".to_string(),
            ),
            (
                "MAESTRO_EVALOPS_ACCESS_TOKEN_FILE".to_string(),
                sandboxwich_core::MAESTRO_HOSTED_RUNNER_GATEWAY_TOKEN_FILE.to_string(),
            ),
            (
                "MAESTRO_EVALOPS_BASE_URL".to_string(),
                sandboxwich_core::MAESTRO_HOSTED_RUNNER_GATEWAY_BASE_URL.to_string(),
            ),
            ("MAESTRO_EVALOPS_ORG_ID".to_string(), "org-1".to_string()),
            (
                "MAESTRO_EVALOPS_WORKSPACE_ID".to_string(),
                "workspace-1".to_string(),
            ),
            (
                "MAESTRO_EVALOPS_PROVIDER".to_string(),
                "openrouter".to_string(),
            ),
            (
                "MAESTRO_EVALOPS_ENVIRONMENT".to_string(),
                "production".to_string(),
            ),
            (
                "MAESTRO_EVALOPS_CREDENTIAL_NAME".to_string(),
                "dex".to_string(),
            ),
            (
                "MAESTRO_DEFAULT_MODEL".to_string(),
                "evalops/gpt-5.5".to_string(),
            ),
            (
                "MAESTRO_LLM_GATEWAY_URL".to_string(),
                sandboxwich_core::MAESTRO_HOSTED_RUNNER_GATEWAY_BASE_URL.to_string(),
            ),
            (
                "MAESTRO_LLM_GATEWAY_ORG_ID".to_string(),
                "org-1".to_string(),
            ),
        ]),
        bootstrap: Some(IsolatedResidentProcessBootstrap {
            content: b"managed-gateway-token".to_vec(),
            target_file: sandboxwich_core::MAESTRO_HOSTED_RUNNER_GATEWAY_TOKEN_FILE.to_string(),
            mode: 0o400,
            placement_attestation: None,
        }),
    }
}

#[test]
fn maestro_hosted_runner_rejects_workspace_modes_without_a_shareable_pvc() {
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        "kubectl",
    )
    .with_maestro_hosted_runner_image(Some(format!(
        "ghcr.io/evalops/maestro@sha256:{}",
        "a".repeat(64)
    )));
    for mode in [WorkspaceMode::Ephemeral, WorkspaceMode::GenericEphemeral] {
        let mut spec = maestro_hosted_runner_spec();
        spec.workspace_mode = mode;
        assert!(
            provider
                .isolated_resident_process_manifests(&spec)
                .expect_err("ephemeral Maestro workspace must fail closed")
                .to_string()
                .contains("persistent workspace")
        );
    }
}

#[test]
fn maestro_hosted_runner_mounts_the_authoritative_managed_home_claim() {
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        "kubectl",
    )
    .with_maestro_hosted_runner_image(Some(format!(
        "ghcr.io/evalops/maestro@sha256:{}",
        "a".repeat(64)
    )));
    let mut spec = maestro_hosted_runner_spec();
    let home_id = Uuid::now_v7();
    spec.workspace_claim_name = Some(format!("sandboxwich-home-{home_id}"));
    let manifests = provider
        .isolated_resident_process_manifests(&spec)
        .expect("persistent managed-home workspace must render");
    let pod = manifests
        .iter()
        .find(|manifest| manifest["kind"] == "Pod")
        .expect("Maestro Pod");
    assert_eq!(
        pod["spec"]["volumes"][2]["persistentVolumeClaim"]["claimName"],
        format!("sandboxwich-home-{home_id}")
    );
}

#[test]
fn maestro_hosted_runner_uses_only_projected_identity_in_an_isolated_pod() {
    let image = format!("ghcr.io/evalops/maestro@sha256:{}", "a".repeat(64));
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-control", None, None)
            .with_sandbox_namespace(Some("sandboxwich-sandboxes".to_string()))
            .with_ingress_namespace(Some("evalops".to_string()))
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string()))
            .with_isolated_sidecar_https_cidrs(vec!["10.40.0.10/32".parse().expect("CIDR")])
            .expect("narrow issuer egress"),
        "kubectl",
    )
    .with_maestro_hosted_runner_image(Some(image.clone()));
    let spec = maestro_hosted_runner_spec();
    let manifests = provider
        .isolated_resident_process_manifests(&spec)
        .expect("projected-identity Maestro sidecar should render");

    assert_eq!(manifests.len(), 4, "managed gateway bootstrap is a Secret");
    assert_eq!(manifests[0]["kind"], "Secret");
    assert_eq!(manifests[1]["kind"], "NetworkPolicy");
    assert_eq!(manifests[2]["kind"], "Service");
    assert_eq!(manifests[3]["kind"], "Pod");
    let secret = &manifests[0];
    let policy = &manifests[1];
    let service = &manifests[2];
    let pod = &manifests[3];
    assert_eq!(
        pod["spec"]["serviceAccountName"],
        sandboxwich_core::MAESTRO_HOSTED_RUNNER_SERVICE_ACCOUNT
    );
    assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
    assert_eq!(pod["spec"]["hostPID"], false);
    assert_eq!(pod["spec"]["hostIPC"], false);
    assert_eq!(pod["spec"]["hostNetwork"], false);
    assert_eq!(pod["spec"]["containers"][0]["image"], image);
    assert_eq!(pod["spec"]["containers"][0]["workingDir"], "/workspace");
    assert!(
        pod["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["name"] == "MAESTRO_WORKSPACE_ROOT" && entry["value"] == "/workspace"
            }),
        "Sandboxwich must author Maestro's durable workspace root"
    );
    assert_eq!(
        pod["spec"]["containers"][0]["securityContext"]["runAsUser"],
        65532
    );
    assert_eq!(
        pod["spec"]["containers"][0]["securityContext"]["runAsGroup"],
        65532
    );
    assert_eq!(pod["spec"]["securityContext"]["fsGroup"], 10001);
    assert_eq!(
        pod["spec"]["securityContext"]["supplementalGroups"],
        serde_json::json!([10001])
    );
    assert_eq!(
        pod["spec"]["affinity"]["podAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
            ["topologyKey"],
        "kubernetes.io/hostname"
    );
    assert_eq!(
        pod["spec"]["affinity"]["podAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
            ["labelSelector"]["matchLabels"]["sandboxwich.dev/sandbox-id"],
        spec.sandbox_id.to_string()
    );
    assert_eq!(
        pod["spec"]["affinity"]["podAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][0]
            ["labelSelector"]["matchLabels"]["sandboxwich.dev/component"],
        "runtime"
    );
    assert_eq!(
        pod["spec"]["volumes"][1]["projected"]["sources"][0]["serviceAccountToken"]["audience"],
        sandboxwich_core::MAESTRO_HOSTED_RUNNER_TOKEN_AUDIENCE
    );
    assert_eq!(
        pod["spec"]["volumes"][1]["projected"]["sources"][0]["serviceAccountToken"]["expirationSeconds"],
        600
    );
    assert_eq!(
        pod["spec"]["volumes"][1]["projected"]["sources"][1]["secret"]["name"],
        sandboxwich_core::MAESTRO_HOSTED_RUNNER_IDENTITY_CA_SECRET
    );
    assert_eq!(
        pod["spec"]["containers"][0]["volumeMounts"][1]["mountPath"],
        sandboxwich_core::MAESTRO_HOSTED_RUNNER_TOKEN_DIRECTORY
    );
    assert!(
        pod["spec"]["containers"][0]["volumeMounts"][1]
            .get("subPath")
            .is_none(),
        "projected-token rotation requires mounting the containing directory"
    );
    assert_eq!(
        pod["spec"]["containers"][0]["volumeMounts"][2],
        serde_json::json!({
            "name": "workspace",
            "mountPath": "/workspace"
        })
    );
    assert_eq!(
        pod["spec"]["volumes"][2],
        serde_json::json!({
            "name": "workspace",
            "persistentVolumeClaim": {
                "claimName": format!("sandboxwich-pvc-{}", spec.sandbox_id)
            }
        })
    );
    assert_eq!(
        pod["spec"]["initContainers"],
        serde_json::json!([]),
        "workspace sharing must not add a privileged init container or quota request"
    );
    assert_eq!(
        service["spec"]["ports"][0]["port"],
        sandboxwich_core::MAESTRO_HOSTED_RUNNER_CONTAINER_PORT
    );
    assert_eq!(
        policy["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"]["app"],
        "runner-host"
    );
    assert!(
        policy["spec"]["egress"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| {
                rule["to"][0]["podSelector"]["matchLabels"]["app"] == "identity"
                    && rule["ports"][0]["port"] == 8080
            }),
        "Maestro residents must reach identity for workload-certificate exchange"
    );
    assert!(
        policy["spec"]["egress"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| {
                let apps: Vec<_> = rule["to"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|entry| entry["podSelector"]["matchLabels"]["app"].as_str())
                    .collect();
                apps.contains(&"llm-gateway")
                    && apps.contains(&"llm-gateway-canary")
                    && rule["ports"][0]["port"] == 8080
            }),
        "Maestro residents must reach the managed EvalOps llm-gateway (stable + canary)"
    );
    assert_eq!(
        secret["data"]["bootstrap"],
        general_purpose::STANDARD.encode(b"managed-gateway-token")
    );
    let rendered = serde_json::to_string(&manifests).expect("render manifests");
    assert!(rendered.contains("\"kind\":\"Secret\""));
    assert!(!rendered.contains("\"cidr\":\"0.0.0.0/0\""));
    assert!(!rendered.contains("MAESTRO_HOSTED_RUNNER_AUTH_TOKEN"));

    let guest = provider.dry_run.pod_manifest(
        spec.sandbox_id,
        &SandboxProvisionSpec {
            workspace_mode: WorkspaceMode::Persistent,
            ..SandboxProvisionSpec::default()
        },
    );
    let rendered_guest = serde_json::to_string(&guest).expect("render guest Pod");
    assert!(!rendered_guest.contains("workload-identity"));
    assert!(!rendered_guest.contains(MAESTRO_HOSTED_RUNNER_TOKEN_DIRECTORY));

    let cleanup = provider.isolated_resident_process_cleanup_manifests(&spec);
    assert!(
        cleanup.iter().any(|manifest| manifest["kind"] == "Secret"),
        "resident teardown must remove the managed-gateway bootstrap Secret"
    );
}

#[test]
fn maestro_hosted_runner_rejects_unapproved_bootstrap_path() {
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        "kubectl",
    )
    .with_maestro_hosted_runner_image(Some(format!(
        "ghcr.io/evalops/maestro@sha256:{}",
        "a".repeat(64)
    )));
    let mut spec = maestro_hosted_runner_spec();
    spec.bootstrap = Some(IsolatedResidentProcessBootstrap {
        content: b"forbidden-bearer".to_vec(),
        target_file: "/run/sandboxwich/bootstrap/token".into(),
        mode: 0o400,
        placement_attestation: None,
    });
    assert!(
        provider
            .isolated_resident_process_manifests(&spec)
            .expect_err("Maestro bootstrap path must fail closed")
            .to_string()
            .contains("path or mode is invalid")
    );
}

#[test]
fn maestro_hosted_runner_rejects_bearer_values_in_resident_environment() {
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        "kubectl",
    )
    .with_maestro_hosted_runner_image(Some(format!(
        "ghcr.io/evalops/maestro@sha256:{}",
        "a".repeat(64)
    )));
    let mut spec = maestro_hosted_runner_spec();
    spec.env.insert(
        "MAESTRO_EVALOPS_ACCESS_TOKEN".into(),
        "must-not-be-persisted".into(),
    );
    assert!(
        provider
            .isolated_resident_process_manifests(&spec)
            .expect_err("Maestro resident env must not carry a bearer value")
            .to_string()
            .contains("forbids bearer values in resident environment")
    );
}

#[test]
fn maestro_hosted_runner_rejects_redirected_identity_exchange() {
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        "kubectl",
    )
    .with_maestro_hosted_runner_image(Some(format!(
        "ghcr.io/evalops/maestro@sha256:{}",
        "a".repeat(64)
    )));
    let mut spec = maestro_hosted_runner_spec();
    spec.env.insert(
        "MAESTRO_IDENTITY_EXCHANGE_URL".into(),
        "https://attacker.internal.example/exchange".into(),
    );
    assert!(
        provider
            .isolated_resident_process_manifests(&spec)
            .expect_err("redirected Identity exchange must fail closed")
            .to_string()
            .contains("canonical Identity exchange URL")
    );
}

#[test]
fn isolated_sidecar_v2_mounts_attestation_as_a_separate_secret_file() {
    let image = format!("ghcr.io/evalops/orb-sidecar@sha256:{}", "d".repeat(64));
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        "kubectl",
    )
    .with_isolated_resident_process_image(Some(image));
    let mut spec = isolated_sidecar_spec(b"orb-bootstrap-canary");
    spec.bootstrap
        .as_mut()
        .expect("orb bootstrap")
        .placement_attestation = Some(b"placement-attestation-canary".to_vec());

    let manifests = provider
        .isolated_resident_process_manifests(&spec)
        .expect("a v2 isolated sidecar should render");
    let secret = &manifests[0];
    let pod = &manifests[2];
    assert_eq!(
        secret["data"]["placement-attestation"],
        general_purpose::STANDARD.encode(b"placement-attestation-canary")
    );
    let items = pod["spec"]["volumes"][0]["secret"]["items"]
        .as_array()
        .expect("secret items");
    assert!(items.iter().any(|item| {
        item["key"] == "placement-attestation"
            && item["path"] == "placement-attestation"
            && item["mode"] == 0o400
    }));
    let init = &pod["spec"]["initContainers"][0];
    assert_eq!(init["name"], "bootstrap-handoff");
    assert_eq!(init["volumeMounts"][0]["name"], "bootstrap-source");
    assert_eq!(init["volumeMounts"][0]["readOnly"], true);
    assert_eq!(init["volumeMounts"][1]["name"], "bootstrap");
    assert_eq!(pod["spec"]["volumes"][1]["emptyDir"]["medium"], "Memory");
    let main_mounts = pod["spec"]["containers"][0]["volumeMounts"]
        .as_array()
        .unwrap();
    assert!(main_mounts.iter().any(|mount| {
        mount["name"] == "bootstrap"
            && mount["mountPath"] == RESIDENT_PROCESS_BOOTSTRAP_PREFIX
            && mount.get("readOnly").is_none()
    }));
    assert!(
        !main_mounts
            .iter()
            .any(|mount| mount["name"] == "bootstrap-source")
    );
    let rendered = serde_json::to_string(&manifests).unwrap();
    assert!(!rendered.contains("placement-attestation-canary"));
    let encoded_attestation = general_purpose::STANDARD.encode(b"placement-attestation-canary");
    assert!(
        !serde_json::to_string(&manifests[1])
            .unwrap()
            .contains(&encoded_attestation)
    );
    assert!(
        !serde_json::to_string(&manifests[2])
            .unwrap()
            .contains(&encoded_attestation)
    );
    let debug = format!("{spec:?}");
    assert!(!debug.contains("placement-attestation-canary"));
    assert!(!debug.contains(&encoded_attestation));
}

#[test]
fn isolated_sidecar_v2_rejects_bootstrap_attestation_path_collision() {
    let image = format!("ghcr.io/evalops/orb-sidecar@sha256:{}", "f".repeat(64));
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        "kubectl",
    )
    .with_isolated_resident_process_image(Some(image));
    let mut spec = isolated_sidecar_spec(b"bootstrap");
    let bootstrap = spec.bootstrap.as_mut().expect("orb bootstrap");
    bootstrap.target_file = RESIDENT_PLACEMENT_ATTESTATION_FILE.to_string();
    bootstrap.placement_attestation = Some(b"attestation".to_vec());
    let error = provider
        .isolated_resident_process_manifests(&spec)
        .expect_err("the two secret keys must never target the same file");
    assert!(error.to_string().contains("collides"));
}

#[test]
fn isolated_sidecar_private_https_cidrs_are_exact_deduplicated_and_sidecar_only() {
    let image = format!("ghcr.io/evalops/orb-sidecar@sha256:{}", "e".repeat(64));
    let dry_run =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string()))
            .with_isolated_sidecar_https_cidrs(vec![
                " 10.20.30.0/24 ".to_string(),
                "10.20.30.0/24".to_string(),
                "fd12:3456:789a::/64".to_string(),
            ])
            .expect("narrow private issuer CIDRs should be accepted");
    let provider = KubernetesApplyProvider::new(dry_run.clone(), "kubectl")
        .with_isolated_resident_process_image(Some(image));
    let manifests = provider
        .isolated_resident_process_manifests(&isolated_sidecar_spec(b"bootstrap"))
        .expect("isolated sidecar should render");
    let egress = manifests[1]["spec"]["egress"].as_array().unwrap();
    let exact_https = egress
        .iter()
        .filter(|rule| {
            rule["ports"] == json!([{ "protocol": "TCP", "port": 443 }])
                && matches!(
                    rule["to"][0]["ipBlock"]["cidr"].as_str(),
                    Some("10.20.30.0/24" | "fd12:3456:789a::/64")
                )
        })
        .collect::<Vec<_>>();
    assert_eq!(exact_https.len(), 2);
    assert!(
        exact_https
            .iter()
            .all(|rule| { rule["to"][0]["ipBlock"].get("except").is_none() })
    );
    assert_eq!(egress[0]["ports"][0]["port"], 53);
    assert!(egress.iter().any(|rule| {
        rule["to"][0]["ipBlock"]["cidr"] == "0.0.0.0/0" && rule["ports"][0]["port"] == 443
    }));
    assert_eq!(manifests[1]["spec"]["ingress"], json!([]));

    let ordinary = dry_run
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec {
                network_egress: NetworkEgress::DenyAll,
                ..SandboxProvisionSpec::default()
            },
            &CancelSignal::never_cancelled(),
        )
        .expect("ordinary sandbox plan");
    let ordinary_json = serde_json::to_string(&ordinary).unwrap();
    assert!(!ordinary_json.contains("10.20.30.0/24"));
    assert!(!ordinary_json.contains("fd12:3456:789a::/64"));
}

#[test]
fn isolated_sidecar_private_https_cidrs_reject_unsafe_destinations() {
    for cidr in [
        "not-a-cidr",
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/23",
        "fd12:3456::/63",
        "169.254.169.254/32",
        "fe80::/64",
        "127.0.0.1/32",
        "::1/128",
        "224.0.0.0/24",
        "ff00::/64",
        "::ffff:169.254.169.254/128",
    ] {
        let result =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_isolated_sidecar_https_cidrs(vec![cidr.to_string()]);
        assert!(
            result.is_err(),
            "unsafe destination {cidr} must be rejected"
        );
    }
}

#[test]
fn isolated_sidecar_manifests_are_separate_fenced_and_secret_safe() {
    let image = format!("ghcr.io/evalops/orb-sidecar@sha256:{}", "b".repeat(64));
    let provider = KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        "kubectl",
    )
    .with_isolated_resident_process_image(Some(image.clone()));
    let bootstrap = b"isolated-bootstrap-canary";
    let spec = isolated_sidecar_spec(bootstrap);

    let manifests = provider
        .isolated_resident_process_manifests(&spec)
        .expect("a configured isolated sidecar should render");
    assert_eq!(manifests.len(), 3);
    let secret = &manifests[0];
    let policy = &manifests[1];
    let pod = &manifests[2];
    assert_eq!(secret["kind"], "Secret");
    assert_eq!(secret["immutable"], true);
    assert_eq!(pod["kind"], "Pod");
    assert_eq!(policy["kind"], "NetworkPolicy");
    assert_eq!(policy["spec"]["policyTypes"], json!(["Ingress", "Egress"]));
    assert_eq!(policy["spec"]["ingress"], json!([]));
    assert_eq!(policy["spec"]["egress"][0]["ports"][0]["port"], 53);
    assert_eq!(
        policy["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"]["k8s-app"],
        "kube-dns"
    );
    assert_eq!(policy["spec"]["egress"][1]["ports"][0]["port"], 443);
    assert!(
        policy["spec"]["egress"][1]["to"][0]["ipBlock"]["except"]
            .as_array()
            .unwrap()
            .contains(&json!("169.254.0.0/16"))
    );
    assert_eq!(
        policy["spec"]["podSelector"]["matchLabels"],
        pod["metadata"]["labels"]
    );
    assert_eq!(
        pod["metadata"]["labels"]["sandboxwich.dev/sandbox-id"],
        spec.sandbox_id.to_string()
    );
    assert_eq!(
        pod["metadata"]["labels"]["sandboxwich.dev/resident-process-id"],
        spec.process_id.to_string()
    );
    assert_eq!(pod["metadata"]["labels"]["sandboxwich.dev/generation"], "7");
    assert_eq!(
        pod["metadata"]["labels"]["sandboxwich.dev/lease-id"],
        spec.lease_id.to_string()
    );
    assert_eq!(pod["spec"]["runtimeClassName"], "gvisor");
    assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
    assert_eq!(pod["spec"]["hostNetwork"], false);
    assert_eq!(pod["spec"]["hostPID"], false);
    assert_eq!(pod["spec"]["hostIPC"], false);
    assert_eq!(pod["spec"]["containers"][0]["image"], image);
    assert_eq!(
        pod["spec"]["containers"][0]["securityContext"]["runAsNonRoot"],
        true
    );
    assert_eq!(
        pod["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"],
        false
    );
    assert_eq!(
        pod["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"],
        true
    );
    assert_eq!(
        pod["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"],
        json!(["ALL"])
    );
    assert_eq!(
        pod["spec"]["containers"][0]["resources"]["requests"]["memory"],
        "64Mi"
    );
    assert_eq!(
        pod["spec"]["containers"][0]["resources"]["limits"]["memory"],
        "256Mi"
    );
    assert_eq!(
        secret["data"]["bootstrap"],
        general_purpose::STANDARD.encode(bootstrap)
    );
    assert!(secret["data"].get("placement-attestation").is_none());
    assert_eq!(
        pod["spec"]["volumes"][0]["secret"]["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    for manifest in &manifests {
        let name = manifest["metadata"]["name"].as_str().unwrap();
        assert!(name.len() <= 63);
        assert!(name.contains("-g7-"));
    }

    let mut replacement = spec.clone();
    replacement.generation += 1;
    replacement.lease_id = Uuid::now_v7();
    let replacement_manifests = provider
        .isolated_resident_process_manifests(&replacement)
        .expect("replacement lease should render separately fenced resources");
    for (old, new) in manifests.iter().zip(&replacement_manifests) {
        assert_ne!(old["metadata"]["name"], new["metadata"]["name"]);
    }

    let debug = format!("{spec:?}");
    assert!(!debug.contains("isolated-bootstrap-canary"));
    assert!(!debug.contains("https://orb.invalid"));
    let cleanup = provider.isolated_resident_process_cleanup_manifests(&spec);
    assert_eq!(cleanup.len(), manifests.len());
    for applied in &manifests {
        assert!(cleanup.iter().any(|deleted| {
            applied["kind"] == deleted["kind"]
                && applied["metadata"]["name"] == deleted["metadata"]["name"]
        }));
    }
    let cleanup_json = serde_json::to_string(&cleanup).unwrap();
    assert!(!cleanup_json.contains("isolated-bootstrap-canary"));
    assert!(!cleanup_json.contains(&general_purpose::STANDARD.encode(bootstrap)));
}

#[test]
fn isolated_sidecar_requires_digest_image_and_runtime_class() {
    let base =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = isolated_sidecar_spec(b"secret");
    let unpinned = KubernetesApplyProvider::new(base.clone(), "kubectl")
        .with_isolated_resident_process_image(Some("ghcr.io/evalops/orb-sidecar:latest".into()));
    assert!(unpinned.isolated_resident_process_manifests(&spec).is_err());
    let no_runtime_class =
        KubernetesApplyProvider::new(base, "kubectl").with_isolated_resident_process_image(Some(
            format!("ghcr.io/evalops/orb-sidecar@sha256:{}", "c".repeat(64)),
        ));
    assert!(
        no_runtime_class
            .isolated_resident_process_manifests(&spec)
            .is_err()
    );
}

#[test]
fn dry_run_does_not_claim_or_execute_isolated_resident_processes() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    assert!(
        !provider
            .capability_report()
            .labels
            .contains_key("provider_isolated_resident_process_version")
    );
    let error = provider
        .run_isolated_resident_process(
            &isolated_sidecar_spec(b"secret"),
            &CancelSignal::never_cancelled(),
            &mut |_| Ok(()),
        )
        .expect_err("dry-run cannot provide a real process isolation boundary");
    assert!(error.to_string().contains("unavailable in dry-run mode"));
}

fn write_isolated_sidecar_fake_kubectl(
    fail_apply: bool,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-isolated-sidecar-kubectl-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create isolated sidecar fake kubectl dir");
    let script_path = dir.join("kubectl");
    let log_path = dir.join("kubectl.log");
    let script = format!(
        r#"#!/bin/sh
set -eu
dir=$(dirname "$0")
printf 'ARGS %s\n' "$*" >> "$dir/kubectl.log"
verb=""
for arg in "$@"; do
  case "$arg" in apply|get|delete) verb="$arg"; break;; esac
done
case "$verb" in
  apply)
    cat > "$dir/apply.stdin"
    if [ "{fail_apply}" = "true" ]; then
      echo "synthetic apply failure" >&2
      exit 1
    fi
    ;;
  get)
    count=0
    if [ -f "$dir/get.count" ]; then count=$(cat "$dir/get.count"); fi
    count=$((count + 1))
    printf '%s' "$count" > "$dir/get.count"
    if [ "$count" -eq 1 ]; then
      printf '%s\n' '{{"metadata":{{"uid":"pod-uid-1"}},"status":{{"phase":"Running","containerStatuses":[{{"ready":true,"state":{{"running":{{}}}}}}]}}}}'
    else
      printf '%s\n' '{{"metadata":{{"uid":"pod-uid-1"}},"status":{{"phase":"Succeeded","containerStatuses":[{{"ready":false,"state":{{"terminated":{{"exitCode":0}}}}}}]}}}}'
    fi
    ;;
  delete)
    cat > "$dir/delete.stdin"
    ;;
  *)
    echo "unsupported fake kubectl invocation: $*" >&2
    exit 2
    ;;
esac
"#
    );
    std::fs::write(&script_path, script).expect("write isolated sidecar fake kubectl");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat isolated sidecar fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions)
            .expect("chmod isolated sidecar fake kubectl");
    }
    (script_path, log_path)
}

fn write_pending_isolated_sidecar_fake_kubectl() -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-pending-sidecar-kubectl-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create pending sidecar fake kubectl dir");
    let script_path = dir.join("kubectl");
    let log_path = dir.join("kubectl.log");
    let script = r#"#!/bin/sh
set -eu
dir=$(dirname "$0")
printf 'ARGS %s\n' "$*" >> "$dir/kubectl.log"
verb=""
for arg in "$@"; do
  case "$arg" in apply|get|delete) verb="$arg"; break;; esac
done
case "$verb" in
  apply) cat > "$dir/apply.stdin" ;;
  get)
    count=0
    if [ -f "$dir/get.count" ]; then count=$(cat "$dir/get.count"); fi
    count=$((count + 1))
    printf '%s' "$count" > "$dir/get.count"
    printf '%s\n' '{"metadata":{"uid":"pending-pod-uid"},"status":{"phase":"Pending","containerStatuses":[{"ready":false,"state":{"waiting":{"reason":"ImagePullBackOff"}}}]}}'
    ;;
  delete) cat > "$dir/delete.stdin" ;;
  *) exit 2 ;;
esac
"#;
    std::fs::write(&script_path, script).expect("write pending sidecar fake kubectl");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat pending sidecar fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions)
            .expect("chmod pending sidecar fake kubectl");
    }
    (script_path, log_path)
}

fn isolated_sidecar_apply_provider(kubectl: &std::path::Path) -> KubernetesApplyProvider {
    KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("in-cluster", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string())),
        kubectl.to_string_lossy().into_owned(),
    )
    .with_kubectl_context(Some("in-cluster".to_string()))
    .with_mutation_gate(true, true)
    .with_isolated_resident_process_image(Some(format!(
        "ghcr.io/evalops/orb-sidecar@sha256:{}",
        "d".repeat(64)
    )))
    .with_isolated_resident_process_poll_intervals(
        Duration::from_millis(5),
        Duration::from_millis(20),
    )
}

#[test]
fn isolated_sidecar_run_observes_terminal_state_and_always_cleans_up() {
    let (kubectl, log_path) = write_isolated_sidecar_fake_kubectl(false);
    let provider = isolated_sidecar_apply_provider(&kubectl);
    assert!(
        provider
            .capability_report()
            .labels
            .get("provider_isolated_resident_process_version")
            .is_some_and(|version| {
                version == PROVIDER_ISOLATED_RESIDENT_PROCESS_VERSION_LABEL_VALUE
            })
    );
    let bootstrap = b"sidecar-lifecycle-canary";
    let spec = isolated_sidecar_spec(bootstrap);
    let mut observations = Vec::new();
    let result = provider
        .run_isolated_resident_process(
            &spec,
            &CancelSignal::never_cancelled(),
            &mut |observation| {
                observations.push(observation);
                Ok(())
            },
        )
        .expect("fake isolated sidecar should complete");
    assert_eq!(
        observations
            .iter()
            .map(|observation| observation.state)
            .collect::<Vec<_>>(),
        vec![
            IsolatedResidentProcessState::Running,
            IsolatedResidentProcessState::Succeeded
        ]
    );
    assert_eq!(
        result.final_observation.state,
        IsolatedResidentProcessState::Succeeded
    );
    assert_eq!(result.final_observation.exit_code, Some(0));

    let dir = kubectl.parent().expect("fake kubectl parent");
    let apply_stdin = std::fs::read_to_string(dir.join("apply.stdin")).unwrap();
    let delete_stdin = std::fs::read_to_string(dir.join("delete.stdin")).unwrap();
    let encoded = general_purpose::STANDARD.encode(bootstrap);
    assert!(apply_stdin.contains(&encoded));
    assert!(!delete_stdin.contains(&encoded));
    assert!(!delete_stdin.contains("sidecar-lifecycle-canary"));
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.lines().any(|line| line.contains(" apply ")));
    assert!(log.lines().any(|line| line.contains(" delete ")));
    assert!(!log.contains("sidecar-lifecycle-canary"));
    assert!(!log.contains(&encoded));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn isolated_sidecar_apply_failure_preserves_typed_kubernetes_output() {
    let (kubectl, _log_path) = write_isolated_sidecar_fake_kubectl(true);
    let provider = isolated_sidecar_apply_provider(&kubectl);
    let error = provider
        .run_isolated_resident_process(
            &isolated_sidecar_spec(b"apply-failure-canary"),
            &CancelSignal::never_cancelled(),
            &mut |_| Ok(()),
        )
        .expect_err("fake kubectl apply must fail");
    let provider_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ProviderError>())
        .expect("isolated apply failures must retain provider classification");
    assert_eq!(
        provider_error.error_class(),
        ProvisioningErrorClass::RetryableProvider
    );
    assert_eq!(
        provider_error.reason_code(),
        "kubernetes_provider_transient"
    );
    assert!(
        error
            .to_string()
            .contains("kubectl apply isolated resident-process manifests failed")
    );
    assert!(error.to_string().contains("synthetic apply failure"));
    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn isolated_sidecar_pending_publishes_identity_and_times_out_retryably() {
    let (kubectl, log_path) = write_pending_isolated_sidecar_fake_kubectl();
    let provider = isolated_sidecar_apply_provider(&kubectl)
        .with_isolated_resident_process_startup_timeout(Duration::from_millis(500));
    let spec = isolated_sidecar_spec(b"pending-deadline-canary");
    let mut observations = Vec::new();
    let error = provider
        .run_isolated_resident_process(
            &spec,
            &CancelSignal::never_cancelled(),
            &mut |observation| {
                observations.push(observation);
                Ok(())
            },
        )
        .expect_err("a permanently Pending sidecar must hit its startup deadline");
    assert!(error.to_string().contains("startup deadline"));
    assert!(
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<ProviderError>())
            .is_some_and(|error| error.disposition() == RetryDisposition::Retryable)
    );
    assert_eq!(observations.len(), 2);
    assert_eq!(
        observations[0].state,
        IsolatedResidentProcessState::Starting
    );
    assert_eq!(
        observations[0].pod_name,
        isolated_resident_process_pod_name(&spec)
    );
    assert_eq!(observations[0].pod_uid.as_deref(), Some("pending-pod-uid"));
    assert_eq!(observations[1].state, IsolatedResidentProcessState::Failed);
    assert_eq!(observations[1].pod_uid.as_deref(), Some("pending-pod-uid"));

    let dir = kubectl.parent().expect("pending fake kubectl parent");
    let get_count: usize = std::fs::read_to_string(dir.join("get.count"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        get_count <= 30,
        "bounded backoff should cap API calls during the 500ms deadline, got {get_count}"
    );
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.lines().any(|line| line.contains(" delete ")));
    assert!(!log.contains("pending-deadline-canary"));
    let delete_stdin = std::fs::read_to_string(dir.join("delete.stdin")).unwrap();
    assert!(!delete_stdin.contains("pending-deadline-canary"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn isolated_sidecar_apply_failure_and_cancellation_attempt_cleanup() {
    let (failing_kubectl, failing_log) = write_isolated_sidecar_fake_kubectl(true);
    let provider = isolated_sidecar_apply_provider(&failing_kubectl);
    let error = provider
        .run_isolated_resident_process(
            &isolated_sidecar_spec(b"apply-failure-canary"),
            &CancelSignal::never_cancelled(),
            &mut |_| Ok(()),
        )
        .expect_err("apply failure must fail closed");
    assert!(error.to_string().contains("kubectl apply"));
    let log = std::fs::read_to_string(&failing_log).unwrap();
    assert!(log.lines().any(|line| line.contains(" delete ")));
    let _ = std::fs::remove_dir_all(
        failing_kubectl
            .parent()
            .expect("failing fake kubectl parent"),
    );

    let (cancel_kubectl, cancel_log) = write_isolated_sidecar_fake_kubectl(false);
    let provider = isolated_sidecar_apply_provider(&cancel_kubectl);
    let cancelled = CancelSignal::new();
    cancelled.cancel();
    let error = provider
        .run_isolated_resident_process(
            &isolated_sidecar_spec(b"cancel-canary"),
            &cancelled,
            &mut |_| Ok(()),
        )
        .expect_err("cancelled isolated sidecar must fail closed");
    assert!(error.to_string().contains("cancel"));
    let log = std::fs::read_to_string(&cancel_log).unwrap();
    assert!(log.lines().any(|line| line.contains(" delete ")));
    let _ = std::fs::remove_dir_all(cancel_kubectl.parent().expect("cancel fake kubectl parent"));
}

#[tokio::test]
async fn run_kubectl_command_async_succeeds_within_timeout() {
    let output = run_kubectl_command_async(
        "sh",
        &["-c".to_string(), "echo hi && exit 0".to_string()],
        None,
        "test fast command",
        Duration::from_secs(5),
        None,
        DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
    )
    .await
    .expect("fast command should succeed well within the timeout");
    assert!(output.success);
    assert_eq!(output.stdout.trim(), "hi");
}

#[tokio::test]
async fn run_kubectl_command_async_kills_the_child_and_errors_on_timeout() {
    // Regression test for item 3(b): before this fix, `run_kubectl_command`
    // used `std::process::Command::output()` with no bound at all, so a
    // wedged `kubectl` (e.g. `kubectl exec` into an unresponsive pod, or
    // `kubectl` stuck talking to an unreachable API server) hung the
    // worker's job-execution thread forever. A command that would run far
    // longer than the configured timeout must be killed and reported as a
    // distinct timeout failure well before it would naturally exit.
    let started = std::time::Instant::now();
    let error = run_kubectl_command_async(
        "sh",
        &["-c".to_string(), "sleep 30".to_string()],
        None,
        "test slow command",
        Duration::from_millis(200),
        None,
        DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
    )
    .await
    .expect_err("a command that outlives the timeout must be treated as a failure");
    let elapsed = started.elapsed();

    assert!(
        error.to_string().contains("timed out"),
        "error should be distinctly reported as a timeout, got: {error}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the timed-out child should have been killed almost immediately instead of \
             the caller waiting anywhere near its full 30s sleep; elapsed = {elapsed:?}"
    );
}

#[tokio::test]
async fn run_kubectl_command_async_is_cancelled_when_lease_renewal_is_lost() {
    // Regression test for item 4(b): before this fix, `handle_lease`'s
    // renewal task just logged and looped when renewal failed, while the
    // job kept executing regardless -- it could be re-queued and picked
    // up by another worker while this one was still running `kubectl
    // exec` for it. A lost-renewal signal must cancel the in-flight
    // kubectl invocation promptly instead of letting it run to
    // completion.
    let cancelled = CancelSignal::new();
    let flip_cancelled = cancelled.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        flip_cancelled.cancel();
    });

    let started = std::time::Instant::now();
    let error = run_kubectl_command_async(
        "sh",
        &["-c".to_string(), "sleep 30".to_string()],
        None,
        "test slow command",
        Duration::from_secs(60), // Long enough that the timeout branch can't win the race.
        Some(&cancelled),
        DEFAULT_MAX_CAPTURED_OUTPUT_BYTES,
    )
    .await
    .expect_err("a cancelled kubectl invocation must be treated as a failure");
    let elapsed = started.elapsed();

    assert!(
        error.to_string().contains("cancelled"),
        "error should be distinctly reported as a cancellation, got: {error}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the cancelled child should have been killed almost immediately instead of \
             the caller waiting anywhere near its full 30s sleep or 60s timeout; \
             elapsed = {elapsed:?}"
    );
}

#[test]
fn kubernetes_dry_run_reports_k8s_capabilities_and_health() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );

    let capabilities = provider.capability_report();
    assert_eq!(capabilities.provider, "kubernetes");
    assert!(
        capabilities
            .capabilities
            .contains(&WorkerCapability::K8sPod)
    );
    assert!(
        capabilities
            .capabilities
            .contains(&WorkerCapability::Snapshot)
    );
    assert!(
        !capabilities
            .capabilities
            .contains(&WorkerCapability::AgentPrompt)
    );
    assert!(
        !capabilities
            .capabilities
            .contains(&WorkerCapability::MaterializeFile),
        "dry-run provider reports must not claim destination attestation"
    );
    assert_eq!(
        capabilities.labels.get("storage_class").map(String::as_str),
        Some("local-path")
    );

    let health = provider.health_report();
    assert_eq!(health.status, ProviderHealthStatus::Healthy);
    assert_eq!(health.provider, "kubernetes");
}

#[test]
fn kubernetes_dry_run_covers_provider_smoke_path_without_cluster_mutation() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let sandbox_id = SandboxId::new();
    let child_sandbox_id = SandboxId::new();
    let snapshot_id = SnapshotId::new();
    let spec = SandboxProvisionSpec::default();

    let provisioned = provider
        .provision(sandbox_id, &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    assert_eq!(provisioned.metadata["mode"], "dry_run");
    assert_eq!(provisioned.metadata["operation"], "provision");
    assert_eq!(
        provisioned.metadata["runtime"]["image"],
        DEFAULT_SANDBOX_GUEST_IMAGE
    );
    assert_eq!(provisioned.metadata["manifests"]["pod"]["kind"], "Pod");
    assert_eq!(
        provisioned.metadata["manifests"]["pod"]["spec"]["containers"][0]["image"],
        DEFAULT_SANDBOX_GUEST_IMAGE
    );
    assert_eq!(
        provisioned.metadata["manifests"]["pod"]["spec"]["securityContext"]["runAsNonRoot"],
        true
    );
    assert_eq!(
        provisioned.metadata["manifests"]["networkPolicy"]["kind"],
        "NetworkPolicy"
    );
    assert_eq!(
        provisioned.metadata["manifests"]["sshService"]["kind"],
        "Service"
    );
    assert_eq!(
        provisioned.metadata["manifests"]["desktopService"]["kind"],
        "Service"
    );

    let exec = provider
        .exec_handoff(
            sandbox_id,
            &spec,
            AgentCommandRequest {
                argv: vec!["echo".to_string(), "hello".to_string()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: None,
                timeout_secs: None,
            },
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run exec should succeed");
    assert_eq!(exec.exit_code, Some(0));
    assert!(exec.stdout.contains("\"operation\":\"exec\""));

    let snapshot = provider
        .create_snapshot(sandbox_id, snapshot_id, &CancelSignal::never_cancelled())
        .expect("dry-run snapshot should succeed");
    assert_eq!(snapshot.metadata["operation"], "snapshot");
    assert_eq!(
        snapshot.metadata["manifests"]["volumeSnapshot"]["kind"],
        "VolumeSnapshot"
    );

    let fork = provider
        .fork(
            sandbox_id,
            child_sandbox_id,
            snapshot_id,
            &spec,
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run fork should succeed");
    assert_eq!(fork.metadata["operation"], "fork");
    assert_eq!(fork.provider, "kubernetes");
    assert_eq!(
        fork.metadata["manifests"]["pvc"]["kind"],
        "PersistentVolumeClaim"
    );
    assert_eq!(
        fork.metadata["manifests"]["pvc"]["spec"]["dataSource"]["kind"],
        "VolumeSnapshot"
    );
    assert_eq!(fork.metadata["manifests"]["sshService"]["kind"], "Service");
}

#[test]
fn kubernetes_dry_run_uses_configured_runtime_image() {
    let runtime_image = "ghcr.io/evalops/sandboxwich-ubuntu-dev:sha-test".to_string();
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_runtime_image(Some(runtime_image.clone()));

    let capabilities = provider.capability_report();
    assert_eq!(
        capabilities.labels.get("runtime_image").map(String::as_str),
        Some(runtime_image.as_str())
    );

    let provisioned = provider
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run provision should succeed");
    assert_eq!(
        provisioned.metadata["runtime"]["image"],
        runtime_image.as_str()
    );
    assert_eq!(
        provisioned.metadata["manifests"]["pod"]["spec"]["containers"][0]["image"],
        runtime_image.as_str()
    );
    assert_eq!(
        provisioned.metadata["manifests"]["pod"]["spec"]["containers"][0]["imagePullPolicy"],
        "IfNotPresent"
    );
}

#[test]
fn apex_trusted_supervisor_profile_is_closed_and_minimally_privileged() {
    let runtime_image = format!("ghcr.io/evalops/apex@sha256:{}", "a".repeat(64));
    let configured =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_runtime_image(Some(runtime_image.clone()))
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string()))
            .with_apex_trusted_supervisor_v1(true);
    let spec = SandboxProvisionSpec {
        runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
        execution_class: ExecutionClass::SandboxedContainer,
        network_egress: NetworkEgress::DenyAll,
        ..SandboxProvisionSpec::default()
    };

    let report = configured.capability_report();
    assert!(
        report
            .capabilities
            .contains(&WorkerCapability::ApexTrustedSupervisorV1)
    );
    assert!(
        report
            .capabilities
            .contains(&WorkerCapability::ApexTaskInstructions)
    );
    assert!(
        report
            .capabilities
            .contains(&WorkerCapability::SandboxedContainer)
    );
    assert_eq!(
        report.labels.get("runtime_profile").map(String::as_str),
        Some("apex_trusted_supervisor_v1")
    );
    assert_eq!(report.labels.get("runtime_image"), Some(&runtime_image));

    let provisioned = configured
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("configured APEX supervisor profile should render");
    let pod = &provisioned.metadata["manifests"]["pod"]["spec"];
    assert_eq!(pod["runtimeClassName"], "gvisor");
    assert_eq!(pod["automountServiceAccountToken"], false);
    assert_eq!(pod["securityContext"]["runAsUser"], 0);
    assert_eq!(pod["securityContext"]["runAsGroup"], 0);
    assert_eq!(pod["securityContext"]["fsGroup"], 10001);
    assert_eq!(
        pod["securityContext"]["seccompProfile"]["type"],
        "RuntimeDefault"
    );
    let container = &pod["containers"][0]["securityContext"];
    assert_eq!(container["allowPrivilegeEscalation"], false);
    assert_eq!(container["runAsUser"], 0);
    assert_eq!(container["capabilities"]["drop"], json!(["ALL"]));
    assert_eq!(
        container["capabilities"]["add"],
        json!(["CHOWN", "SETGID", "SETUID", "KILL", "DAC_READ_SEARCH"])
    );

    let unconfigured =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_runtime_image(Some(runtime_image.clone()))
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string()));
    assert!(
        unconfigured
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .is_err()
    );

    let wrong_isolation =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_runtime_image(Some(runtime_image))
            .with_apex_trusted_supervisor_v1(true);
    assert!(
        wrong_isolation
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .is_err(),
        "the provider boundary must reject APEX on development isolation"
    );
    assert!(
        !wrong_isolation
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::ApexTrustedSupervisorV1),
        "an invalid APEX isolation configuration must not advertise APEX capability"
    );

    for network_egress in [
        NetworkEgress::AllowAll,
        NetworkEgress::Allowlist {
            rules: vec![NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "not-a-cidr".to_string(),
            }],
        },
    ] {
        let rejected = SandboxProvisionSpec {
            runtime_profile: SandboxRuntimeProfile::ApexTrustedSupervisorV1,
            execution_class: ExecutionClass::SandboxedContainer,
            network_egress,
            ..SandboxProvisionSpec::default()
        };
        assert!(
            configured
                .provision(
                    SandboxId::new(),
                    &rejected,
                    &CancelSignal::never_cancelled()
                )
                .is_err(),
            "provider must independently reject unsafe APEX egress"
        );
    }
}

#[test]
fn virtual_machine_execution_class_requires_kata_and_runtime_class() {
    let spec = SandboxProvisionSpec {
        execution_class: ExecutionClass::VirtualMachine,
        network_egress: NetworkEgress::DenyAll,
        ..SandboxProvisionSpec::default()
    };

    let kata =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Kata)
            .with_runtime_class_name(Some("kata-qemu".to_string()));
    let provisioned = kata
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("kata worker with a RuntimeClass renders VM-class work");
    assert_eq!(
        provisioned.metadata["manifests"]["pod"]["spec"]["runtimeClassName"],
        "kata-qemu"
    );

    let development =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    assert!(
        development
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .is_err(),
        "the provider boundary must reject VM-class work on development isolation"
    );

    let kata_without_runtime_class =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Kata);
    assert!(
        kata_without_runtime_class
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .is_err(),
        "VM-class work must fail closed without a RuntimeClass"
    );
}

#[test]
fn provision_staged_rejects_vm_class_before_applying_anything() {
    // provision_staged is the path the job runner uses (main.rs), and it builds
    // the Pod with `pod_manifest`, which renders JSON without validating. The
    // other route to validate_runtime_profile -- dry_run.provision -- is reached
    // only after the Pod is Ready, so a check that ran there would reject the
    // workload after it had already executed. This asserts nothing is applied.
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let spec = SandboxProvisionSpec {
        execution_class: ExecutionClass::VirtualMachine,
        network_egress: NetworkEgress::DenyAll,
        ..SandboxProvisionSpec::default()
    };

    let mut reports = Vec::new();
    let error = provider
        .provision_staged(
            SandboxId::new(),
            &spec,
            &CancelSignal::never_cancelled(),
            |report| {
                reports.push(report);
                Ok(())
            },
        )
        .expect_err("VM-class work must be rejected on a development-isolation provider");
    assert!(
        format!("{error:#}")
            .contains("virtual_machine execution_class requires the kata isolation profile"),
        "rejected for the wrong reason: {error:#}"
    );

    // Fail closed: the rejection must precede every mutation and every stage.
    assert!(
        reports.is_empty(),
        "no provisioning stage may be reported before the execution class is accepted: {reports:?}"
    );
    let invocations = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        invocations.trim().is_empty(),
        "no kubectl invocation expected, got: {invocations}"
    );
}

#[test]
fn sandboxed_container_execution_class_requires_gvisor_and_runtime_class() {
    let spec = SandboxProvisionSpec {
        execution_class: ExecutionClass::SandboxedContainer,
        network_egress: NetworkEgress::DenyAll,
        ..SandboxProvisionSpec::default()
    };

    let gvisor =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string()));
    gvisor
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("gvisor worker with a RuntimeClass renders sandboxed-container work");

    // A RuntimeClass alone is not an isolation profile: production workers run
    // with `--runtime-class-name gvisor` and the default development profile.
    let runtime_class_only =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_runtime_class_name(Some("gvisor".to_string()));
    let error = runtime_class_only
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("sandboxed-container work must fail closed without the gvisor profile");
    assert!(
        format!("{error:#}")
            .contains("sandboxed_container execution_class requires the gvisor isolation profile"),
        "rejected for the wrong reason: {error:#}"
    );

    let kata =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Kata)
            .with_runtime_class_name(Some("kata-qemu".to_string()));
    assert!(
        kata.provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .is_err(),
        "a Kata worker must not silently satisfy sandboxed_container work"
    );
}

/// A fake kubectl whose live Pod reports `observed_runtime_class` (empty means
/// the Pod carries no `runtimeClassName` at all), and whose `get pod` existence
/// probe answers `pod_exists`.
fn write_runtime_class_fake_kubectl(
    observed_runtime_class: &str,
    pod_exists: bool,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-runtime-class-kubectl-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create runtime class fake kubectl dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{log}"
case " $* " in
  *runtimeClassName*) printf '%s' '{observed}' ;;
  *" get volumesnapshot "*|*" get volumesnapshot/"*)
    case " $* " in
      *boundVolumeSnapshotContentName*) printf 'true|snapcontent-test|local-path-snapshot|' ;;
      *readyToUse*) printf 'true' ;;
    esac
    ;;
  *" get pod "*) printf '%s' '{existing}' ;;
  *" exec "*) cat >/dev/null 2>&1 || true; printf 'guest-ran' ;;
  *) cat >/dev/null 2>&1 || true ;;
esac
"#,
        log = log_path.display(),
        observed = observed_runtime_class,
        existing = if pod_exists {
            "pod/sandboxwich-guest"
        } else {
            ""
        },
    );
    std::fs::write(&script_path, script).expect("write runtime class fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat runtime class fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions)
            .expect("chmod runtime class fake kubectl");
    }
    (script_path, log_path)
}

fn kata_apply_provider(kubectl: &std::path::Path) -> KubernetesApplyProvider {
    KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class(
            "k3s-ci",
            "sandboxwich-ci",
            None,
            Some("local-path-snapshot".to_string()),
        )
        .with_isolation_profile(IsolationProfile::Kata)
        .with_runtime_class_name(Some("kata-qemu".to_string())),
        kubectl.to_string_lossy().into_owned(),
    )
    .with_kubectl_context(Some("in-cluster".to_string()))
    .with_mutation_gate(true, true)
}

fn virtual_machine_spec() -> SandboxProvisionSpec {
    SandboxProvisionSpec {
        execution_class: ExecutionClass::VirtualMachine,
        network_egress: NetworkEgress::DenyAll,
        ..SandboxProvisionSpec::default()
    }
}

#[test]
fn virtual_machine_provision_fails_closed_when_the_live_pod_lost_its_runtime_class() {
    // Rendering `runtimeClassName` is not evidence that the admitted Pod runs
    // under it: a mutating webhook may strip the field, leaving an ordinary
    // container that would otherwise be reported as a ready VM sandbox.
    let (kubectl, log_path) = write_runtime_class_fake_kubectl("", false);
    let provider = kata_apply_provider(&kubectl);
    let spec = virtual_machine_spec();

    let error = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("a pod without the required RuntimeClass must not become a VM sandbox");
    let provider_error = error
        .downcast_ref::<ProviderError>()
        .expect("boundary failures are typed provider errors");
    assert_eq!(
        provider_error.reason_code(),
        "runtime_class_boundary_unverified"
    );
    assert_eq!(provider_error.disposition(), RetryDisposition::Permanent);
    assert_eq!(
        provider_error.error_class(),
        ProvisioningErrorClass::TerminalSecurity
    );
    let invocations = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        !invocations.contains(" exec "),
        "no guest work may run behind an unverified boundary: {invocations}"
    );
    assert!(
        invocations.contains(" delete "),
        "the rejected sandbox's resources must be torn down: {invocations}"
    );
}

#[test]
fn virtual_machine_provision_staged_fails_closed_on_a_mismatched_runtime_class() {
    let (kubectl, log_path) = write_stateful_fake_kubectl_with_observed_runtime_class("gvisor");
    let provider = kata_apply_provider(&kubectl);
    let spec = virtual_machine_spec();

    let mut reports = Vec::new();
    let error = provider
        .provision_staged(
            SandboxId::new(),
            &spec,
            &CancelSignal::never_cancelled(),
            |report| {
                reports.push(report);
                Ok(())
            },
        )
        .expect_err("a pod running under another RuntimeClass must fail closed");
    assert_eq!(
        error
            .downcast_ref::<ProviderError>()
            .expect("boundary failures are typed provider errors")
            .reason_code(),
        "runtime_class_boundary_unverified"
    );
    assert!(
        !reports
            .iter()
            .any(|report| report.stage == ProvisioningStage::SandboxReady),
        "an unverified sandbox must never be reported ready: {reports:?}"
    );
    let invocations = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(!invocations.contains(" exec "), "{invocations}");
}

#[test]
fn virtual_machine_exec_reverifies_the_boundary_of_an_existing_pod() {
    let (kubectl, log_path) = write_runtime_class_fake_kubectl("gvisor", true);
    let provider = kata_apply_provider(&kubectl);
    let spec = virtual_machine_spec();

    let error = provider
        .exec_handoff(
            SandboxId::new(),
            &spec,
            AgentCommandRequest {
                argv: vec!["echo".to_string(), "hello".to_string()],
                cwd: None,
                env: BTreeMap::new(),
                stdin: None,
                timeout_secs: None,
            },
            &CancelSignal::never_cancelled(),
        )
        .expect_err("an adopted pod outside the VM boundary must not run guest commands");
    assert_eq!(
        error
            .downcast_ref::<ProviderError>()
            .expect("boundary failures are typed provider errors")
            .reason_code(),
        "runtime_class_boundary_unverified"
    );
    let invocations = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        !invocations.contains(" exec "),
        "no guest command may run in a pod outside the requested boundary: {invocations}"
    );
}

#[test]
fn virtual_machine_provision_succeeds_when_the_live_pod_carries_the_runtime_class() {
    let (kubectl, log_path) = write_runtime_class_fake_kubectl("kata-qemu", false);
    let provider = kata_apply_provider(&kubectl);
    let spec = virtual_machine_spec();

    let handle = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("a verified Kata pod provisions normally");
    assert_eq!(handle.metadata["mode"], "apply");
    let invocations = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        invocations.contains("jsonpath={.spec.runtimeClassName}"),
        "the live boundary must be read from the API server: {invocations}"
    );
    assert!(!invocations.contains(" delete "), "{invocations}");
}

#[test]
fn virtual_machine_fork_fails_closed_when_the_child_pod_lost_its_runtime_class() {
    // A fork inherits the parent's execution class, so a child whose
    // RuntimeClass was stripped would present an ordinary container as a VM.
    let (kubectl, log_path) = write_runtime_class_fake_kubectl("", false);
    let provider = kata_apply_provider(&kubectl);
    let spec = virtual_machine_spec();

    let error = provider
        .fork(
            SandboxId::new(),
            SandboxId::new(),
            SnapshotId::new(),
            &spec,
            &CancelSignal::never_cancelled(),
        )
        .expect_err("a forked pod outside the VM boundary must not be reported ready");
    assert_eq!(
        error
            .downcast_ref::<ProviderError>()
            .expect("boundary failures are typed provider errors")
            .reason_code(),
        "runtime_class_boundary_unverified"
    );
    let invocations = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(!invocations.contains(" exec "), "{invocations}");
    assert!(
        invocations.contains(" delete "),
        "the rejected fork's resources must be torn down: {invocations}"
    );
}

#[test]
fn development_container_provision_does_not_read_the_pod_runtime_class() {
    let (kubectl, log_path) = write_runtime_class_fake_kubectl("", false);
    let provider = apply_provider_with_fake_kubectl(&kubectl);

    provider
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec {
                network_egress: NetworkEgress::DenyAll,
                ..SandboxProvisionSpec::default()
            },
            &CancelSignal::never_cancelled(),
        )
        .expect("development-container work is unaffected by the RuntimeClass boundary check");
    let invocations = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(!invocations.contains("runtimeClassName"), "{invocations}");
}

#[test]
fn image_pull_policy_tracks_tag_mutability() {
    assert_eq!(
        image_pull_policy_for("ghcr.io/evalops/sandboxwich-ubuntu-dev:latest"),
        "Always"
    );
    assert_eq!(
        image_pull_policy_for("sandboxwich-runtime:conformance"),
        "IfNotPresent"
    );
    assert_eq!(
        image_pull_policy_for("ghcr.io/evalops/sandboxwich-ubuntu-dev@sha256:abc"),
        "IfNotPresent"
    );
    // Registry host:port must not be treated as a tag.
    assert_eq!(image_pull_policy_for("localhost:5000/myimage"), "Always");
    assert_eq!(
        image_pull_policy_for("localhost:5000/myimage:v1"),
        "IfNotPresent"
    );
    assert_eq!(image_pull_policy_for("myimage"), "Always");
}

#[test]
fn digest_pin_validation_requires_an_exact_lowercase_sha256() {
    assert!(image_is_digest_pinned(&format!(
        "ghcr.io/evalops/sandboxwich-worker@sha256:{}",
        "a".repeat(64)
    )));
    for image in [
        "ghcr.io/evalops/sandboxwich-worker:latest",
        "ghcr.io/evalops/sandboxwich-worker@sha256:abc",
        "ghcr.io/evalops/sandboxwich-worker@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(!image_is_digest_pinned(image), "accepted {image}");
    }
}

#[test]
fn kubernetes_dry_run_uses_configured_workspace_storage() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_workspace_storage(Some("2Gi".to_string()));

    let capabilities = provider.capability_report();
    assert_eq!(
        capabilities
            .labels
            .get("workspace_storage")
            .map(String::as_str),
        Some("2Gi")
    );

    let provisioned = provider
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run provision should succeed");
    assert_eq!(
        provisioned.metadata["manifests"]["pvc"]["spec"]["resources"]["requests"]["storage"],
        "2Gi"
    );
}

#[test]
fn kubernetes_workspace_modes_render_distinct_bounded_storage_contracts() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_workspace_storage(Some("3Gi".to_string()));

    for (mode, volume_key, standalone_pvc) in [
        (WorkspaceMode::Ephemeral, "emptyDir", false),
        (WorkspaceMode::GenericEphemeral, "ephemeral", false),
        (WorkspaceMode::Persistent, "persistentVolumeClaim", true),
    ] {
        let spec = SandboxProvisionSpec {
            secret_mounts: Vec::new(),
            workspace_mode: mode.clone(),
            execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::DenyAll,
            runtime_profile: Default::default(),
            ..SandboxProvisionSpec::default()
        };
        let provisioned = provider
            .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
            .expect("workspace mode should render");
        let manifests = &provisioned.metadata["manifests"];
        let volume = &manifests["pod"]["spec"]["volumes"][0];

        assert_eq!(
            provisioned.metadata["workspaceMode"],
            serde_json::json!(mode)
        );
        assert!(
            volume.get(volume_key).is_some(),
            "missing {volume_key}: {volume}"
        );
        assert_eq!(manifests["pvc"].is_null(), !standalone_pvc);

        if mode == WorkspaceMode::Ephemeral {
            assert_eq!(volume["emptyDir"]["sizeLimit"], "1Gi");
            assert_eq!(provisioned.metadata["workspaceStorage"], "1Gi");
            assert_eq!(
                manifests["pod"]["spec"]["containers"][0]["resources"]["limits"]["ephemeral-storage"],
                "1Gi"
            );
        }
        if mode == WorkspaceMode::GenericEphemeral {
            assert_eq!(
                volume["ephemeral"]["volumeClaimTemplate"]["spec"]["resources"]["requests"]["storage"],
                "3Gi"
            );
        }
    }
}

#[test]
fn managed_home_pvc_is_stable_and_not_owned_by_runtime_teardown() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("cluster-a", "sandboxwich", None, None);
    let home_id = HomeId::new();
    let first_runtime = SandboxId::new();
    let second_runtime = SandboxId::new();
    let spec = SandboxProvisionSpec {
        workspace_mode: WorkspaceMode::Persistent,
        ..Default::default()
    };

    let first = provider
        .provision_home_handle(
            first_runtime,
            home_id,
            &spec,
            RuntimeResourceStatus::Planned,
        )
        .unwrap();
    let second = provider
        .provision_home_handle(
            second_runtime,
            home_id,
            &spec,
            RuntimeResourceStatus::Planned,
        )
        .unwrap();
    for handle in [first, second] {
        let pvc = &handle.metadata["manifests"]["pvc"];
        assert_eq!(
            pvc["metadata"]["name"],
            format!("sandboxwich-home-{home_id}")
        );
        assert_eq!(
            pvc["metadata"]["labels"]["sandboxwich.dev/home-id"],
            home_id.to_string()
        );
        assert!(pvc["metadata"]["labels"]["sandboxwich.dev/sandbox-id"].is_null());
        assert!(handle.resources.iter().all(|resource| {
            resource.resource_kind != RuntimeResourceKind::PersistentVolumeClaim
        }));
    }
}

#[test]
fn configured_workspace_storage_overrides_non_default_tier_disk_size() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_workspace_storage(Some("20Gi".to_string()));
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    assert_eq!(
        provisioned.metadata["manifests"]["pvc"]["spec"]["resources"]["requests"]["storage"],
        "20Gi"
    );
}

#[test]
fn kubernetes_dry_run_renders_resource_network_and_runtime_class_controls() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Gvisor)
            .with_runtime_class_name(Some("gvisor".to_string()));
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.0.0.0/8".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };
    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let pod = &provisioned.metadata["manifests"]["pod"];
    let network_policy = &provisioned.metadata["manifests"]["networkPolicy"];

    assert_eq!(pod["spec"]["runtimeClassName"], "gvisor");
    assert_eq!(
        pod["spec"]["containers"][0]["resources"]["limits"]["memory"],
        "4Gi"
    );
    assert_eq!(
        pod["spec"]["containers"][0]["resources"]["limits"]["cpu"],
        "1"
    );
    assert_eq!(
        provisioned.metadata["manifests"]["pvc"]["spec"]["resources"]["requests"]["storage"],
        "8Gi"
    );
    assert_eq!(
        network_policy["spec"]["egress"][0]["to"][0]["ipBlock"]["cidr"],
        "10.0.0.0/8"
    );
    assert_eq!(
        pod["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"][0],
        "ALL"
    );
    assert!(
        provider
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::SandboxedContainer)
    );
    assert!(
        !provider
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::VirtualMachine)
    );
    assert!(
        !provider
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::GvisorSandbox)
    );
}

#[test]
fn kubernetes_dry_run_reports_exact_typed_isolation_capability() {
    let development =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_runtime_class_name(Some("arbitrary-runtime".to_string()));
    assert!(
        !development
            .capability_report()
            .capabilities
            .iter()
            .any(|capability| matches!(
                capability,
                WorkerCapability::SandboxedContainer | WorkerCapability::VirtualMachine
            ))
    );

    // A simulated provision never starts a guest, so a dry-run report must not
    // claim the VM boundary even when the operator configured Kata. Only the
    // apply provider built from the same configuration advertises it.
    let kata =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Kata)
            .with_runtime_class_name(Some("kata-qemu".to_string()));
    assert!(
        !kata
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::VirtualMachine)
    );
    assert!(
        !kata
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::SandboxedContainer)
    );
    assert!(
        KubernetesApplyProvider::new(kata, "kubectl")
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::VirtualMachine)
    );

    let kata_without_runtime_class =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Kata);
    assert!(
        !KubernetesApplyProvider::new(kata_without_runtime_class, "kubectl")
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::VirtualMachine)
    );
}

#[test]
fn kubernetes_dry_run_rejects_host_allow_rules_for_standard_network_policy() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let error = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("host allow rules should not silently render deny-all");
    assert!(error.to_string().contains("egress_gateway_image_required"));
}

#[test]
fn cilium_fqdn_backend_renders_host_allow_rules() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_cilium_fqdn_egress(true);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("configured Cilium must support host allow rules");
    let policy = &provisioned.metadata["manifests"]["networkPolicy"];
    assert_eq!(policy["apiVersion"], "cilium.io/v2");
    assert_eq!(policy["kind"], "CiliumNetworkPolicy");
    assert_eq!(
        policy["spec"]["egress"][0]["toFQDNs"][0]["matchName"],
        "api.example.com"
    );
    assert!(
        provider
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::FqdnEgress)
    );
}

#[test]
fn cilium_fqdn_backend_renders_controlled_wildcards_as_patterns() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_cilium_fqdn_egress(true);
    let spec = SandboxProvisionSpec {
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "*.packages.example.com".to_string(),
            }],
        },
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("configured Cilium must support controlled wildcard rules");
    assert_eq!(
        provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"][0]["toFQDNs"][0]["matchPattern"],
        "*.packages.example.com"
    );
}

/// Cilium learns FQDN-to-address bindings only from DNS answers its proxy
/// observes, and it only proxies DNS carrying an L7 `rules.dns` selector.
/// Without this rule the `toFQDNs` cache stays empty and every allowlisted
/// name is unreachable, which the live conformance suite reproduces.
#[test]
fn cilium_fqdn_backend_proxies_dns_so_the_allowlist_resolves() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_cilium_fqdn_egress(true);
    let policy = provider
        .render_egress_policy(SandboxId::new(), &host_allowlist("api.example.com"))
        .expect("configured Cilium must render host allow rules");

    let dns_rule = policy["spec"]["egress"]
        .as_array()
        .expect("egress rules")
        .iter()
        .find(|rule| rule["toEndpoints"][0]["matchLabels"]["k8s:k8s-app"] == "kube-dns")
        .expect("cluster DNS egress rule");
    assert_eq!(dns_rule["toPorts"][0]["ports"][0]["port"], "53");
    assert_eq!(
        dns_rule["toPorts"][0]["rules"]["dns"],
        json!([{"matchPattern": "*"}])
    );
}

/// The egress-gateway backend proxies HTTP and HTTPS only; the Cilium backend
/// has to scope allowlisted names the same way, or the same allowlist grants a
/// wider boundary depending on which backend rendered it.
#[test]
fn cilium_fqdn_backend_scopes_allowed_hosts_to_http_ports() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_cilium_fqdn_egress(true);
    let policy = provider
        .render_egress_policy(SandboxId::new(), &host_allowlist("api.example.com"))
        .expect("configured Cilium must render host allow rules");

    assert_eq!(
        policy["spec"]["egress"][0]["toPorts"][0]["ports"],
        json!([
            {"port": "80", "protocol": "TCP"},
            {"port": "443", "protocol": "TCP"}
        ])
    );
}

/// A name resolving into the metadata or control-plane range must not become
/// reachable just because it is on the allowlist.
#[test]
fn cilium_fqdn_backend_denies_the_excluded_ranges_alongside_the_allowlist() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_cilium_fqdn_egress(true);
    let policy = provider
        .render_egress_policy(SandboxId::new(), &host_allowlist("api.example.com"))
        .expect("configured Cilium must render host allow rules");

    let denied: Vec<_> = policy["spec"]["egressDeny"][0]["toCIDRSet"]
        .as_array()
        .expect("egressDeny CIDR set")
        .iter()
        .map(|entry| entry["cidr"].as_str().expect("cidr").to_string())
        .collect();
    assert!(denied.contains(&"169.254.0.0/16".to_string()), "{policy}");
}

#[test]
fn cilium_fqdn_backend_rejects_an_unparseable_cidr_allow_rule() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_cilium_fqdn_egress(true);
    let network_egress = NetworkEgress::Allowlist {
        rules: vec![
            sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            },
            sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.0.0.0/33".to_string(),
            },
        ],
    };

    provider
        .render_egress_policy(SandboxId::new(), &network_egress)
        .expect_err("an unparseable CIDR must fail closed instead of panicking");
}

fn host_allowlist(host: &str) -> NetworkEgress {
    NetworkEgress::Allowlist {
        rules: vec![sandboxwich_core::NetworkAllowRule {
            kind: NetworkAllowRuleKind::Host,
            value: host.to_string(),
        }],
    }
}

#[test]
fn host_rules_render_a_separate_gateway_and_no_direct_public_egress() {
    let image = format!(
        "ghcr.io/evalops/sandboxwich-worker@sha256:{}",
        "a".repeat(64)
    );
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("gke-ci", "sandboxwich-ci", None, None)
            .with_egress_gateway_image(Some(image.clone()));
    let sandbox_id = SandboxId::new();
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(sandbox_id, &spec, &CancelSignal::never_cancelled())
        .expect("digest-pinned gateway must support host rules");
    let gateway = &provisioned.metadata["manifests"]["egressGatewayPod"];
    let service = &provisioned.metadata["manifests"]["egressGatewayService"];
    let sandbox_policy = &provisioned.metadata["manifests"]["networkPolicy"];
    let gateway_policy = &provisioned.metadata["manifests"]["egressGatewayNetworkPolicy"];
    assert_eq!(gateway["kind"], "Pod");
    assert_eq!(gateway["spec"]["containers"][0]["image"], image);
    assert_eq!(
        gateway["spec"]["containers"][0]["args"][0],
        "egress-gateway"
    );
    for probe in ["readinessProbe", "livenessProbe"] {
        assert_eq!(
            gateway["spec"]["containers"][0][probe]["exec"]["command"],
            json!(["/usr/local/bin/sandboxwich", "egress-gateway-health"])
        );
        assert!(gateway["spec"]["containers"][0][probe]["tcpSocket"].is_null());
    }
    assert_eq!(service["kind"], "Service");
    assert_eq!(
        sandbox_policy["spec"]["podSelector"]["matchLabels"]["sandboxwich.dev/component"],
        "runtime"
    );
    let sandbox_egress = sandbox_policy["spec"]["egress"].as_array().unwrap();
    assert!(
        sandbox_egress
            .iter()
            .any(|rule| rule["ports"][0]["port"] == 8080)
    );
    assert!(!sandbox_egress.iter().any(|rule| {
        rule["to"].as_array().is_some_and(|peers| {
            peers
                .iter()
                .any(|peer| peer["ipBlock"]["cidr"] == "0.0.0.0/0")
        })
    }));
    let serialized_gateway_policy = serde_json::to_string(gateway_policy).unwrap();
    assert!(serialized_gateway_policy.contains("169.254.0.0/16"));
    assert!(serialized_gateway_policy.contains("10.0.0.0/8"));
    assert!(!serialized_gateway_policy.contains("::ffff:"));
    let serialized_runtime_policy = gateway["spec"]["containers"][0]["env"][0]["value"]
        .as_str()
        .expect("gateway policy environment is serialized JSON");
    assert!(serialized_runtime_policy.contains("::ffff:0.0.0.0/96"));
    assert!(
        provider
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::FqdnEgress)
    );
}

#[test]
fn node_local_dns_is_allowed_only_on_dns_ports_for_runtime_and_gateway() {
    let image = format!(
        "ghcr.io/evalops/sandboxwich-worker@sha256:{}",
        "a".repeat(64)
    );
    let node_local_dns = "169.254.20.10".parse().unwrap();
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("gke-ci", "sandboxwich-ci", None, None)
            .with_egress_gateway_image(Some(image))
            .with_dns_service_ips(vec![node_local_dns]);
    let spec = SandboxProvisionSpec {
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "example.com".to_string(),
            }],
        },
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("node-local DNS must compose with the protected link-local carve-out");

    for policy_name in ["networkPolicy", "egressGatewayNetworkPolicy"] {
        let egress = provisioned.metadata["manifests"][policy_name]["spec"]["egress"]
            .as_array()
            .expect("egress rules should be rendered");
        let dns_rule = egress
            .iter()
            .find(|rule| rule["to"][0]["ipBlock"]["cidr"] == "169.254.20.10/32")
            .expect("the configured NodeLocal DNS endpoint must be explicit");
        assert_eq!(
            dns_rule["ports"],
            json!([
                {"protocol": "UDP", "port": 53},
                {"protocol": "TCP", "port": 53}
            ])
        );
    }

    let gateway_egress =
        provisioned.metadata["manifests"]["egressGatewayNetworkPolicy"]["spec"]["egress"]
            .as_array()
            .unwrap();
    assert!(!gateway_egress.iter().any(|rule| {
        rule["to"][0]["ipBlock"]["cidr"] == "169.254.20.10/32"
            && rule["ports"].as_array().is_some_and(|ports| {
                ports
                    .iter()
                    .any(|port| port["port"] == 80 || port["port"] == 443)
            })
    }));
}

#[test]
fn host_rules_reject_an_unpinned_gateway_image() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("gke-ci", "sandboxwich-ci", None, None)
            .with_egress_gateway_image(Some(
                "ghcr.io/evalops/sandboxwich-worker:latest".to_string(),
            ));
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let error = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("host rules must reject a mutable gateway image");
    assert!(error.to_string().contains("egress_gateway_image_unpinned"));
    assert!(
        !provider
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::FqdnEgress),
        "provider-capabilities must not advertise work that provisioning rejects"
    );
}

#[test]
fn kubernetes_pod_mounts_authorized_keys_secret_by_reference() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_ssh_authorized_keys_secret(Some("sandboxwich-authorized-keys".to_string()));
    let provisioned = provider
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run provision should succeed");
    let pod = &provisioned.metadata["manifests"]["pod"];

    assert_eq!(
        provisioned.metadata["runtime"]["sshAuthorizedKeysSecret"],
        "sandboxwich-authorized-keys"
    );
    assert!(
        pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volume mounts should be an array")
            .iter()
            .any(|mount| mount["name"] == "ssh-authorized-keys"
                && mount["mountPath"] == "/run/sandboxwich/ssh"
                && mount["readOnly"] == true)
    );
    assert!(
        pod["spec"]["volumes"]
            .as_array()
            .expect("volumes should be an array")
            .iter()
            .any(|volume| volume["name"] == "ssh-authorized-keys"
                && volume["secret"]["secretName"] == "sandboxwich-authorized-keys"
                && volume["secret"]["items"][0]["key"] == "authorized_keys")
    );
    assert!(
        !serde_json::to_string(pod)
            .expect("pod manifest should serialize")
            .contains("ssh-rsa")
    );
}

#[test]
fn volume_snapshot_manifest_pins_configured_snapshot_class() {
    let with_class = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("standard-rwo".to_string()),
        Some("gke-pd-csi".to_string()),
    );
    let without_class =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let snapshot_id = SnapshotId::new();
    let sandbox_id = SandboxId::new();

    let pinned = with_class.volume_snapshot_manifest(sandbox_id, snapshot_id);
    assert_eq!(pinned["spec"]["volumeSnapshotClassName"], "gke-pd-csi");
    assert_eq!(
        pinned["spec"]["source"]["persistentVolumeClaimName"],
        format!("sandboxwich-pvc-{sandbox_id}")
    );

    let unpinned = without_class.volume_snapshot_manifest(sandbox_id, snapshot_id);
    assert!(
        unpinned["spec"].get("volumeSnapshotClassName").is_none(),
        "omitting the class must leave volumeSnapshotClassName unset so dry-run plans stay honest: {unpinned}"
    );
}

#[test]
fn apply_create_snapshot_refuses_when_snapshot_class_is_unconfigured() {
    let (kubectl, log_path) = write_fake_kubectl(None);
    let provider = apply_provider_with_fake_kubectl_and_snapshot_class(&kubectl, None);

    let error = provider
        .create_snapshot(
            SandboxId::new(),
            SnapshotId::new(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("apply mode must fail closed without a CSI VolumeSnapshotClass");
    assert!(
        error
            .to_string()
            .contains("snapshot class is not configured"),
        "expected a configuration error, got: {error}"
    );
    assert!(
        !log_path.exists()
            || std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .is_empty(),
        "no kubectl mutation may run before the class gate"
    );
    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn apply_create_snapshot_waits_for_ready_to_use_before_success() {
    let (kubectl, log_path) = write_fake_kubectl(None);
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();
    let snapshot_id = SnapshotId::new();

    let handle = provider
        .create_snapshot(sandbox_id, snapshot_id, &CancelSignal::never_cancelled())
        .expect("configured apply snapshot should succeed once readyToUse");
    assert!(
        handle
            .resources
            .iter()
            .all(|resource| resource.status == RuntimeResourceStatus::Ready),
        "snapshot resources must be Ready only after readyToUse, got: {:?}",
        handle.resources
    );
    assert_eq!(handle.metadata["mode"], "apply");
    assert!(handle.metadata.get("waitStatus").is_some());

    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        log.contains(" apply "),
        "snapshot object must be applied: {log}"
    );
    assert!(
        log.contains(" wait ")
            && log.contains("readyToUse")
            && log.contains(&format!(
                "volumesnapshot/sandboxwich-snapshot-{snapshot_id}"
            )),
        "create_snapshot must wait for readyToUse on the applied VolumeSnapshot: {log}"
    );
    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn apply_create_snapshot_fails_when_ready_to_use_wait_fails() {
    let (kubectl, log_path) = write_fake_kubectl(Some("wait"));
    let provider = apply_provider_with_fake_kubectl(&kubectl);

    let error = provider
        .create_snapshot(
            SandboxId::new(),
            SnapshotId::new(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("a VolumeSnapshot that never becomes readyToUse must fail the job");
    assert!(
        error.to_string().contains("readyToUse"),
        "expected a readyToUse wait failure, got: {error}"
    );
    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        log.contains(" apply "),
        "apply should have run before wait: {log}"
    );
    assert!(
        log.contains(" wait "),
        "wait should have been attempted: {log}"
    );
    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn apply_fork_refuses_unready_volume_snapshot() {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-fake-kubectl-unready-snap-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create fake kubectl dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    // ready|boundContent|class|error — not ready
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> \"{log}\"\n\
         case \" $* \" in\n\
         *boundVolumeSnapshotContentName*) printf 'false|snapcontent-x|local-path-snapshot|' ;;\n\
         *readyToUse*) printf 'false' ;;\n\
         *\" apply \"*) cat >/dev/null 2>&1 || true ;;\n\
         esac\n\
         exit 0\n",
        log = log_path.display(),
    );
    std::fs::write(&script_path, script).expect("write fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    let snapshot_id = SnapshotId::new();

    let error = provider
        .fork(
            SandboxId::new(),
            SandboxId::new(),
            snapshot_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("fork must not apply a PVC against an unbound VolumeSnapshot");
    assert!(
        error.to_string().contains("snapshot_not_ready")
            || error.to_string().contains("not readyToUse")
            || error.to_string().contains("not restorable"),
        "expected unbound-snapshot refusal, got: {error}"
    );
    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        !log.contains(" apply "),
        "no fork manifests may be applied when the snapshot is unbound: {log}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn apply_fork_refuses_ready_but_unbound_volume_snapshot() {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-fake-kubectl-unbound-content-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create fake kubectl dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> \"{log}\"\n\
         case \" $* \" in\n\
         *boundVolumeSnapshotContentName*) printf 'true||local-path-snapshot|' ;;\n\
         *\" apply \"*) cat >/dev/null 2>&1 || true ;;\n\
         esac\n\
         exit 0\n",
        log = log_path.display(),
    );
    std::fs::write(&script_path, script).expect("write fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);

    let error = provider
        .fork(
            SandboxId::new(),
            SandboxId::new(),
            SnapshotId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("fork must refuse when bound content is missing");
    assert!(
        error.to_string().contains("snapshot_unbound")
            || error.to_string().contains("boundVolumeSnapshotContentName"),
        "expected unbound-content refusal, got: {error}"
    );
    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        !log.contains(" apply "),
        "no fork manifests may be applied without bound content: {log}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn apply_fork_refuses_poison_volume_snapshot_with_status_error() {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-fake-kubectl-poison-snap-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create fake kubectl dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> \"{log}\"\n\
         case \" $* \" in\n\
         *boundVolumeSnapshotContentName*) printf 'false|||Failed to set default snapshot class' ;;\n\
         *\" apply \"*) cat >/dev/null 2>&1 || true ;;\n\
         esac\n\
         exit 0\n",
        log = log_path.display(),
    );
    std::fs::write(&script_path, script).expect("write fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);

    let error = provider
        .fork(
            SandboxId::new(),
            SandboxId::new(),
            SnapshotId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("fork must refuse poison snapshots");
    assert!(
        error.to_string().contains("snapshot_poison") || error.to_string().contains("status.error"),
        "expected poison refusal, got: {error}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn apply_resume_refuses_unready_volume_snapshot() {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-fake-kubectl-unready-resume-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create fake kubectl dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> \"{log}\"\n\
         case \" $* \" in\n\
         *boundVolumeSnapshotContentName*) printf 'false|snapcontent-x|local-path-snapshot|' ;;\n\
         *readyToUse*) printf 'false' ;;\n\
         *\" apply \"*) cat >/dev/null 2>&1 || true ;;\n\
         esac\n\
         exit 0\n",
        log = log_path.display(),
    );
    std::fs::write(&script_path, script).expect("write fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    let snapshot_id = SnapshotId::new();

    let error = provider
        .resume(
            SandboxId::new(),
            snapshot_id,
            &SandboxProvisionSpec {
                workspace_mode: WorkspaceMode::Persistent,
                ..SandboxProvisionSpec::default()
            },
            &CancelSignal::never_cancelled(),
        )
        .expect_err("resume must not apply a PVC against an unbound VolumeSnapshot");
    assert!(
        error.to_string().contains("snapshot_not_ready")
            || error.to_string().contains("not readyToUse")
            || error.to_string().contains("not restorable"),
        "expected unbound-snapshot refusal, got: {error}"
    );
    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        !log.contains(" apply "),
        "no resume manifests may be applied when the snapshot is unbound: {log}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn apply_stop_waits_for_sandbox_volume_snapshots_before_deleting_pvc() {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-fake-kubectl-stop-snap-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create fake kubectl dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> \"{log}\"\n\
         case \" $* \" in\n\
         *\" get volumesnapshot \"*) printf 'sandboxwich-snapshot-pending\\n' ;;\n\
         *\" wait \"*) ;;\n\
         *\" delete \"*) ;;\n\
         esac\n\
         exit 0\n",
        log = log_path.display(),
    );
    std::fs::write(&script_path, script).expect("write fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    let sandbox_id = SandboxId::new();

    provider
        .stop(
            sandbox_id,
            &SandboxTeardownSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("stop should succeed after waiting for listed VolumeSnapshots");

    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    let get_pos = log.find(" get volumesnapshot ").unwrap_or_else(|| {
        panic!("stop must list VolumeSnapshots first: {log}");
    });
    let wait_pos = log
        .find("volumesnapshot/sandboxwich-snapshot-pending")
        .unwrap_or_else(|| panic!("stop must wait on listed VolumeSnapshots: {log}"));
    let delete_pos = log
        .find(" delete ")
        .unwrap_or_else(|| panic!("stop must still delete core resources: {log}"));
    assert!(
        get_pos < wait_pos && wait_pos < delete_pos,
        "ordering must be list, then wait readyToUse, then delete PVC; log: {log}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn kubernetes_apply_plan_covers_smoke_and_cleanup_without_mutation() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        Some("local-path-snapshot".to_string()),
    );
    let apply = KubernetesApplyProvider::new(provider, "kubectl");
    let plan = apply.smoke_plan(SandboxId::new(), SandboxId::new(), SnapshotId::new());

    assert_eq!(plan.mode, "apply");
    assert_eq!(plan.operation, "smoke");
    assert_eq!(
        plan.apply_args,
        vec![
            "--context",
            "k3s-ci",
            "-n",
            "sandboxwich-ci",
            "apply",
            "-f",
            "-"
        ]
    );
    assert_eq!(
        plan.cleanup_args,
        vec![
            "--context",
            "k3s-ci",
            "-n",
            "sandboxwich-ci",
            "delete",
            "--ignore-not-found=true",
            "-f",
            "-"
        ]
    );
    assert!(plan.apply_manifests.iter().any(|manifest| {
        manifest["kind"] == "VolumeSnapshot"
            && manifest["spec"]["volumeSnapshotClassName"] == "local-path-snapshot"
    }));
    assert!(plan.apply_manifests.iter().any(|manifest| {
        manifest["kind"] == "PersistentVolumeClaim"
            && manifest["spec"]["dataSource"]["kind"] == "VolumeSnapshot"
    }));
    assert!(
        plan.apply_manifests
            .iter()
            .any(|manifest| manifest["kind"] == "Service"
                && manifest["spec"]["ports"][0]["name"] == "ssh")
    );
    assert_eq!(plan.cleanup_manifests.len(), plan.apply_manifests.len());
    assert!(
        !plan
            .apply_manifests
            .iter()
            .any(|manifest| manifest["kind"] == "Secret")
    );
}

#[test]
fn kubernetes_apply_provider_can_use_in_cluster_service_account() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let apply = KubernetesApplyProvider::new(provider, "kubectl")
        .with_kubectl_context(Some("in-cluster".to_string()))
        .with_mutation_gate(true, true);
    let plan = apply.smoke_plan(SandboxId::new(), SandboxId::new(), SnapshotId::new());

    assert!(!plan.apply_args.iter().any(|arg| arg == "--context"));
    assert_eq!(&plan.apply_args[..2], ["-n", "sandboxwich-ci"]);

    let sandbox_id = SandboxId::new();
    let request = AgentCommandRequest {
        argv: vec!["printf".to_string(), "ok".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
        timeout_secs: None,
    };
    let exec_args = apply.exec_args(sandbox_id, &request);

    assert!(!exec_args.iter().any(|arg| arg == "--context"));
    assert_eq!(&exec_args[..2], ["-n", "sandboxwich-ci"]);
    assert!(exec_args.contains(&format!("sandboxwich-{sandbox_id}")));
    assert_eq!(
        &exec_args[exec_args.len() - 2..],
        ["printf".to_string(), "ok".to_string()]
    );
}

#[test]
fn exec_args_never_render_env_values_on_argv() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let apply = KubernetesApplyProvider::new(provider, "kubectl");
    let sandbox_id = SandboxId::new();
    let mut env = BTreeMap::new();
    env.insert(
        "SUPER_SECRET_TOKEN".to_string(),
        "sk-do-not-leak-this-value".to_string(),
    );
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let request = AgentCommandRequest {
        argv: vec!["printf".to_string(), "ok".to_string()],
        cwd: None,
        env,
        stdin: None,
        timeout_secs: None,
    };

    let exec_args = apply.exec_args(sandbox_id, &request);

    // The secret value (and even the innocuous one) must never appear
    // anywhere on argv, whether as a whole arg or embedded in one --
    // /proc/*/cmdline and any local `ps` visibility would otherwise
    // leak it to every other process on the guest, plus the worker
    // host's own process table.
    assert!(
        !exec_args
            .iter()
            .any(|arg| arg.contains("sk-do-not-leak-this-value")),
        "secret value leaked onto kubectl exec argv: {exec_args:?}"
    );
    assert!(
        !exec_args
            .iter()
            .any(|arg| arg.contains("SUPER_SECRET_TOKEN")),
        "env var name leaked onto kubectl exec argv: {exec_args:?}"
    );
    assert!(
        !exec_args.iter().any(|arg| arg == "env"),
        "must not shell out to `env KEY=VALUE ...` positional args anymore"
    );

    // `-i` must be set so kubectl actually connects the payload stdin.
    assert!(exec_args.contains(&"-i".to_string()));
    assert!(exec_args.contains(&"bash".to_string()));
    // The real command must still be intact at the tail of argv.
    assert_eq!(
        &exec_args[exec_args.len() - 2..],
        ["printf".to_string(), "ok".to_string()]
    );
}

#[test]
fn apex_task_instructions_exec_is_fixed_and_accepts_no_caller_process_fields() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let apply = KubernetesApplyProvider::new(provider, "kubectl")
        .with_kubectl_context(Some("in-cluster".to_string()));
    let sandbox_id = SandboxId::new();

    let args = apply.apex_task_instructions_args(sandbox_id);

    assert!(!args.iter().any(|arg| arg == "-i"));
    assert_eq!(
        &args[args.len() - 4..],
        [
            "exec".to_string(),
            format!("sandboxwich-{sandbox_id}"),
            "--".to_string(),
            "/opt/apex/bin/task-instructions".to_string(),
        ]
    );
}

#[test]
fn apex_task_instructions_live_read_returns_exact_bytes_and_rejects_oversize_output() {
    let dir = std::env::temp_dir().join(format!("sandboxwich-apex-read-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create fake kubectl dir");
    let script_path = dir.join("kubectl");
    std::fs::write(
        &script_path,
        "#!/bin/sh\ncase \" $* \" in *\" get pod \"*) printf 'pod/found\\n'; exit 0 ;; esac\nprintf 'private\\000instructions'\n",
    )
    .expect("write fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).unwrap();
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    let output = provider
        .read_apex_task_instructions(SandboxId::new(), &CancelSignal::never_cancelled())
        .expect("fixed live read should succeed");
    assert_eq!(output, b"private\0instructions");

    std::fs::write(
        &script_path,
        format!("#!/bin/sh\ncase \" $* \" in *\" get pod \"*) printf 'pod/found\\n'; exit 0 ;; esac\nhead -c {} /dev/zero\n", APEX_TASK_INSTRUCTIONS_MAX_BYTES + 1),
    )
    .expect("replace fake kubectl");
    let error = provider
        .read_apex_task_instructions(SandboxId::new(), &CancelSignal::never_cancelled())
        .expect_err("more than 1 MiB must be rejected, never truncated");
    assert!(
        error
            .to_string()
            .contains("apex_task_instructions_too_large")
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn exec_args_without_env_do_not_request_stdin_or_a_wrapper() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let apply = KubernetesApplyProvider::new(provider, "kubectl");
    let request = AgentCommandRequest {
        argv: vec!["printf".to_string(), "ok".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
        timeout_secs: None,
    };

    let exec_args = apply.exec_args(SandboxId::new(), &request);

    assert!(!exec_args.contains(&"-i".to_string()));
    assert!(!exec_args.contains(&"bash".to_string()));
    assert!(KubernetesApplyProvider::exec_stdin_payload(&request).is_none());
}

#[test]
fn exec_args_with_command_stdin_request_interactive_transport_without_exposing_bytes() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let apply = KubernetesApplyProvider::new(provider, "kubectl");
    let marker = b"apex-private-input".to_vec();
    let request = AgentCommandRequest {
        argv: vec!["sha256sum".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: Some(marker.clone()),
        timeout_secs: None,
    };

    let exec_args = apply.exec_args(SandboxId::new(), &request);
    let payload = KubernetesApplyProvider::exec_stdin_payload(&request)
        .expect("command stdin should produce a kubectl stdin payload");

    assert!(exec_args.contains(&"-i".to_string()));
    assert_eq!(payload, marker);
    assert!(
        !exec_args
            .iter()
            .any(|arg| arg.contains("apex-private-input"))
    );
    assert!(!format!("{request:?}").contains("apex-private-input"));
}

#[test]
fn exec_args_carry_cwd_through_the_env_wrapper_when_both_are_set() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let apply = KubernetesApplyProvider::new(provider, "kubectl");
    let mut env = BTreeMap::new();
    env.insert("FOO".to_string(), "bar".to_string());
    let request = AgentCommandRequest {
        argv: vec!["pwd".to_string()],
        cwd: Some("/workspace/project".to_string()),
        env,
        stdin: None,
        timeout_secs: None,
    };

    let exec_args = apply.exec_args(SandboxId::new(), &request);

    assert!(exec_args.contains(&"-i".to_string()));
    assert!(exec_args.iter().any(|arg| arg == "/workspace/project"));
    assert_eq!(exec_args[exec_args.len() - 1], "pwd");
    assert!(!exec_args.iter().any(|arg| arg.contains("FOO=bar")));
}

#[test]
fn exec_stdin_payload_nul_delimits_key_value_pairs() {
    let mut env = BTreeMap::new();
    env.insert("A".to_string(), "1".to_string());
    env.insert("B".to_string(), "two".to_string());
    let request = AgentCommandRequest {
        argv: vec!["true".to_string()],
        cwd: None,
        env,
        stdin: None,
        timeout_secs: None,
    };

    let payload = KubernetesApplyProvider::exec_stdin_payload(&request)
        .expect("non-empty env should produce a stdin payload");
    let text = String::from_utf8(payload).expect("payload should be valid utf-8");
    let entries: Vec<&str> = text.split('\0').filter(|s| !s.is_empty()).collect();

    assert!(entries.contains(&"A=1"));
    assert!(entries.contains(&"B=two"));
}

#[test]
fn exec_stdin_payload_preserves_command_bytes_after_the_env_prefix() {
    let mut env = BTreeMap::new();
    env.insert("A".to_string(), "1".to_string());
    env.insert("B".to_string(), "two".to_string());
    let command_stdin = vec![0, b'j', b's', b'o', b'n', b'\n', 255];
    let request = AgentCommandRequest {
        argv: vec!["cat".to_string()],
        cwd: None,
        env,
        stdin: Some(command_stdin.clone()),
        timeout_secs: None,
    };

    let payload = KubernetesApplyProvider::exec_stdin_payload(&request).unwrap();

    assert!(payload.starts_with(b"A=1\0B=two\0"));
    assert!(payload.ends_with(&command_stdin));
}

#[test]
fn provider_mode_distinguishes_apply_execution_from_dry_run_simulation() {
    let dry_run = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let apply = KubernetesApplyProvider::new(dry_run.clone(), "kubectl");

    assert_eq!(
        dry_run.capability_report().labels.get("provider_mode"),
        Some(&"dry_run".to_string())
    );
    assert_eq!(
        apply.capability_report().labels.get("provider_mode"),
        Some(&"apply".to_string())
    );
    assert!(
        !dry_run
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::MaterializeFile)
    );
    assert!(
        apply
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::MaterializeFile)
    );
}

#[test]
fn dry_run_provider_rejects_oversized_stdin_at_its_entrypoint() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let request = AgentCommandRequest {
        argv: vec!["true".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: Some(vec![b'x'; MAX_COMMAND_STDIN_BYTES + 1]),
        timeout_secs: None,
    };

    let error = provider
        .exec_handoff(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            request,
            &CancelSignal::never_cancelled(),
        )
        .expect_err("dry-run provider boundary must reject oversized stdin");

    assert!(error.to_string().contains("command_stdin_too_large"));
}

#[test]
fn apply_provider_rejects_oversized_stdin_before_kubectl_lookup_or_provisioning() {
    let (kubectl, log_path) = write_fake_kubectl(None);
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let request = AgentCommandRequest {
        argv: vec!["true".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: Some(vec![b'x'; MAX_COMMAND_STDIN_BYTES + 1]),
        timeout_secs: None,
    };

    let error = provider
        .exec_handoff(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            request,
            &CancelSignal::never_cancelled(),
        )
        .expect_err("apply provider boundary must reject before kubectl side effects");

    assert!(error.to_string().contains("command_stdin_too_large"));
    assert!(
        !log_path.exists(),
        "validation must run before kubectl lookup"
    );
    let _ = std::fs::remove_dir_all(kubectl.parent().unwrap());
}

#[test]
fn providers_reject_nul_environment_before_guest_or_kubectl_and_preserve_binary_stdin_boundary() {
    let mut env = BTreeMap::new();
    env.insert("VALID_KEY".to_string(), "prefix\0shifted".to_string());
    let binary_stdin = vec![0, 255, b'j', b's', b'o', b'n', b'\n'];
    let request = AgentCommandRequest {
        argv: vec!["cat".to_string()],
        cwd: None,
        env,
        stdin: Some(binary_stdin),
        timeout_secs: None,
    };
    let dry_run = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let dry_error = dry_run
        .exec_handoff(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            request.clone(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("NUL environment value must fail at dry-run provider boundary");
    assert!(
        dry_error
            .to_string()
            .contains("command_environment_contains_nul")
    );

    let mut nul_key_env = BTreeMap::new();
    nul_key_env.insert("BAD\0KEY".to_string(), "value".to_string());
    let nul_key_error = dry_run
        .exec_handoff(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            AgentCommandRequest {
                argv: vec!["cat".to_string()],
                cwd: None,
                env: nul_key_env,
                stdin: Some(vec![0, 255, b'x']),
                timeout_secs: None,
            },
            &CancelSignal::never_cancelled(),
        )
        .expect_err("NUL environment key must fail at provider boundary");
    assert!(
        nul_key_error
            .to_string()
            .contains("command_environment_contains_nul")
    );

    let (kubectl, log_path) = write_fake_kubectl(None);
    let apply = apply_provider_with_fake_kubectl(&kubectl);
    let apply_error = apply
        .exec_handoff(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            request,
            &CancelSignal::never_cancelled(),
        )
        .expect_err("NUL environment value must fail before kubectl or guest start");
    assert!(
        apply_error
            .to_string()
            .contains("command_environment_contains_nul")
    );
    assert!(
        !log_path.exists(),
        "validation must run before kubectl lookup"
    );
    let _ = std::fs::remove_dir_all(kubectl.parent().unwrap());
}

#[test]
fn kubernetes_apply_gate_requires_explicit_double_opt_in() {
    let missing_flag = KubernetesApplyProvider::validate_apply_gate(false, true)
        .expect_err("missing --confirm-apply should fail");
    assert!(missing_flag.to_string().contains("--confirm-apply"));

    let missing_env = KubernetesApplyProvider::validate_apply_gate(true, false)
        .expect_err("missing mutation env should fail");
    assert!(missing_env.to_string().contains(KUBERNETES_MUTATION_ENV));

    KubernetesApplyProvider::validate_apply_gate(true, true)
        .expect("double opt-in should pass validation");
}

#[test]
fn allow_all_egress_carves_out_control_plane_and_dns_ranges() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let policy = &provisioned.metadata["manifests"]["networkPolicy"];

    assert_eq!(policy["spec"]["policyTypes"], json!(["Ingress", "Egress"]));

    let egress = policy["spec"]["egress"]
        .as_array()
        .expect("egress should be an array");
    let open_rule = &egress[0]["to"][0]["ipBlock"];
    assert_eq!(open_rule["cidr"], "0.0.0.0/0");
    let except = open_rule["except"]
        .as_array()
        .expect("0.0.0.0/0 rule should carve out control-plane/link-local ranges");
    let except: Vec<&str> = except.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(except.contains(&"169.254.0.0/16"));
    assert!(except.contains(&"10.42.0.0/16"));
    assert!(except.contains(&"10.43.0.0/16"));

    let dns_rule = egress
        .iter()
        .find(|rule| rule["ports"][0]["port"] == 53)
        .expect("a DNS egress rule should always be present");
    assert_eq!(
        dns_rule["to"][0]["podSelector"]["matchLabels"]["k8s-app"],
        "kube-dns"
    );
    assert_eq!(
        dns_rule["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "kube-system"
    );
    let ports: Vec<(String, i64)> = dns_rule["ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["protocol"].as_str().unwrap().to_string(),
                p["port"].as_i64().unwrap(),
            )
        })
        .collect();
    assert!(ports.contains(&("UDP".to_string(), 53)));
    assert!(ports.contains(&("TCP".to_string(), 53)));
}

#[test]
fn allowlist_egress_carves_out_control_plane_ranges_contained_within_allowed_cidr() {
    // GH-<egress carve-out fix>: `10.0.0.0/8` fully contains the default
    // k3s pod/service ranges (`10.42.0.0/16`, `10.43.0.0/16`), so an
    // allowlist entry that broad must carve them out via `except` just
    // like `0.0.0.0/0` does -- an allowlist CIDR is not exempt from the
    // carve-out just because it isn't exactly `0.0.0.0/0`.
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.0.0.0/8".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
        .as_array()
        .expect("egress should be an array");

    assert_eq!(egress[0]["to"][0]["ipBlock"]["cidr"], "10.0.0.0/8");
    let except: Vec<&str> = egress[0]["to"][0]["ipBlock"]["except"]
        .as_array()
        .expect("10.0.0.0/8 fully contains the k3s pod/service ranges and must carve them out")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(except.contains(&"10.42.0.0/16"));
    assert!(except.contains(&"10.43.0.0/16"));
    // 169.254.0.0/16 doesn't overlap 10.0.0.0/8 at all, so it must not
    // appear as an (invalid, non-subset) except entry.
    assert!(!except.contains(&"169.254.0.0/16"));

    assert!(
        egress.iter().any(|rule| rule["ports"][0]["port"] == 53),
        "allowlist egress must still include a DNS rule so name resolution keeps working"
    );
}

#[test]
fn allowlist_egress_leaves_disjoint_narrow_cidrs_untouched() {
    // A CIDR that shares no addresses with any excluded range gets no
    // `except` at all -- the carve-out logic must not add irrelevant
    // exceptions.
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "192.168.1.0/24".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
        .as_array()
        .expect("egress should be an array");

    assert_eq!(egress[0]["to"][0]["ipBlock"]["cidr"], "192.168.1.0/24");
    assert!(egress[0]["to"][0]["ipBlock"]["except"].is_null());
}

#[test]
fn allowlist_egress_rejects_cidr_fully_covered_by_an_excluded_range() {
    // If the allowed CIDR is entirely inside (or equal to) an excluded
    // range, there is nothing left to allow once the carve-out is
    // applied -- k8s NetworkPolicy also requires `except` entries to be
    // a strict subset of `cidr`, so `except == cidr` isn't just
    // pointless, it's invalid. Reject rather than silently exposing the
    // excluded range or producing a broken manifest.
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "169.254.169.0/24".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let err = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("allowlisting a range fully covered by an excluded CIDR must be rejected");
    assert!(err.to_string().contains("169.254.0.0/16"));
}

#[test]
fn allowlist_egress_rejects_cidr_exactly_equal_to_an_excluded_range() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.42.0.0/16".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("allowlisting a CIDR identical to an excluded range must be rejected");
}

#[test]
fn allowlist_egress_carves_out_control_plane_ranges_when_wide_open_cidr_is_allowed() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "0.0.0.0/0".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
        .as_array()
        .expect("egress should be an array");

    assert!(
        !egress[0]["to"][0]["ipBlock"]["except"]
            .as_array()
            .expect("0.0.0.0/0 allowlist entry should carve out control-plane ranges")
            .is_empty()
    );
}

#[test]
fn ipv6_allowlist_cidr_containing_an_ipv6_excluded_range_carves_it_out() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_egress_excluded_cidrs(vec!["fd00:ec2::254/128".to_string()]);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "fd00::/8".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
        .as_array()
        .expect("egress should be an array");

    assert_eq!(egress[0]["to"][0]["ipBlock"]["cidr"], "fd00::/8");
    let except: Vec<&str> = egress[0]["to"][0]["ipBlock"]["except"]
        .as_array()
        .expect("ipv6 allowlist entry should carve out the overlapping ipv6 excluded range")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(except.contains(&"fd00:ec2::254/128"));
    // The default (ipv4) excluded CIDRs never overlap an ipv6 allow
    // rule, so they must not show up either.
    assert!(!except.contains(&"169.254.0.0/16"));
}

#[test]
fn ipv6_allow_rule_is_unaffected_by_default_ipv4_excluded_cidrs() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "2001:db8::/32".to_string(),
            }],
        },
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
        .as_array()
        .expect("egress should be an array");

    assert_eq!(egress[0]["to"][0]["ipBlock"]["cidr"], "2001:db8::/32");
    assert!(egress[0]["to"][0]["ipBlock"]["except"].is_null());
}

#[test]
fn operator_supplied_egress_excluded_cidrs_merge_with_defaults() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_egress_excluded_cidrs(vec!["172.16.0.0/12".to_string()]);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let except: Vec<&str> = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"][0]
        ["to"][0]["ipBlock"]["except"]
        .as_array()
        .expect("except should be an array")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    // The operator-supplied CIDR is merged in...
    assert!(except.contains(&"172.16.0.0/12"));
    // ...alongside every default, including the metadata carve-out --
    // an override can never silently drop it.
    assert!(except.contains(&"169.254.0.0/16"));
    assert!(except.contains(&"10.42.0.0/16"));
    assert!(except.contains(&"10.43.0.0/16"));
}

#[test]
fn with_egress_excluded_cidrs_replace_drops_the_defaults() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_egress_excluded_cidrs_replace(vec!["172.16.0.0/12".to_string()]);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let except: Vec<&str> = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"][0]
        ["to"][0]["ipBlock"]["except"]
        .as_array()
        .expect("except should be an array")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    assert_eq!(except, vec!["172.16.0.0/12"]);
}

#[test]
fn deny_all_egress_keeps_only_dns_and_authenticated_api_control_plane_rules() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::DenyAll,
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let egress = provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"]
        .as_array()
        .expect("deny-all still needs bounded system egress");
    assert!(egress.iter().any(|rule| rule["ports"][0]["port"] == 53));
    let api = egress
        .iter()
        .find(|rule| rule["ports"][0]["port"] == 3217)
        .expect("guest control channel must reach the API");
    assert_eq!(
        api["to"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "sandboxwich-ci"
    );
    assert_eq!(
        api["to"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"],
        "sandboxwich-api"
    );
}

#[test]
fn network_policy_renders_ingress_rule_restricted_to_control_plane_pods() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let provisioned = provider
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run provision should succeed");
    let policy = &provisioned.metadata["manifests"]["networkPolicy"];

    assert_eq!(policy["spec"]["policyTypes"], json!(["Ingress", "Egress"]));
    let ingress = policy["spec"]["ingress"]
        .as_array()
        .expect("ingress should be an array");
    assert_eq!(ingress.len(), 1);
    let from = &ingress[0]["from"][0];
    assert_eq!(
        from["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "sandboxwich-ci"
    );
    assert_eq!(
        from["podSelector"]["matchLabels"]["app.kubernetes.io/part-of"],
        "sandboxwich"
    );
    let ports: Vec<i64> = ingress[0]["ports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["port"].as_i64().unwrap())
        .collect();
    assert_eq!(ports, vec![2222, 6080, 5900]);
}

#[test]
fn ingress_namespace_and_selector_are_configurable() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_ingress_namespace(Some("sandboxwich-ingress".to_string()))
            .with_ingress_pod_selector(vec![("app".to_string(), "sandboxwich-proxy".to_string())]);
    let provisioned = provider
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run provision should succeed");
    let from = &provisioned.metadata["manifests"]["networkPolicy"]["spec"]["ingress"][0]["from"][0];

    assert_eq!(
        from["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "sandboxwich-ingress"
    );
    assert_eq!(
        from["podSelector"]["matchLabels"]["app"],
        "sandboxwich-proxy"
    );
}

#[test]
fn pod_disables_service_account_token_automount_and_sets_ephemeral_storage_limits() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: Vec::new(),
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
        runtime_profile: Default::default(),
        ..SandboxProvisionSpec::default()
    };
    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let pod = &provisioned.metadata["manifests"]["pod"];

    assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
    assert_eq!(
        pod["spec"]["containers"][0]["resources"]["requests"]["ephemeral-storage"],
        "2Gi"
    );
    assert_eq!(
        pod["spec"]["containers"][0]["resources"]["limits"]["ephemeral-storage"],
        "2Gi"
    );
}

#[test]
fn guest_token_is_mounted_as_a_file_and_redacted_from_provider_metadata() {
    let sandbox_id = SandboxId::new();
    let worker_id = Uuid::new_v4();
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_guest_credentials(
                sandbox_id,
                worker_id,
                "http://sandboxwich-api.evalops.svc.cluster.local:3217",
                "sbw_gtok_supersecret",
            );
    let handle = provider
        .provision(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .unwrap();
    let pod = &handle.metadata["manifests"]["pod"];
    let env = pod["spec"]["containers"][0]["env"].as_array().unwrap();
    assert!(env.iter().any(|entry| {
        entry["name"] == "SANDBOXWICH_GUEST_TOKEN_FILE"
            && entry["value"] == "/run/sandboxwich/guest/api-token"
    }));
    assert!(
        !env.iter()
            .any(|entry| entry["name"] == "SANDBOXWICH_API_TOKEN_FILE")
    );
    assert!(env.iter().any(|entry| {
        entry["name"] == "SANDBOXWICH_SANDBOX_ID" && entry["value"] == sandbox_id.to_string()
    }));
    assert!(env.iter().any(|entry| {
        entry["name"] == "SANDBOXWICH_WORKER_ID" && entry["value"] == worker_id.to_string()
    }));
    let serialized = serde_json::to_string(&handle.metadata).unwrap();
    assert!(!serialized.contains("sbw_gtok_supersecret"));
    assert_eq!(
        handle.metadata["manifests"]["guestTokenSecret"]["stringData"]["api-token"],
        GUEST_TOKEN_REDACTED
    );
}

#[test]
fn runtime_entrypoint_starts_agent_with_guest_token_file() {
    let entrypoint =
        include_str!("../../../../deploy/runtime/ubuntu-dev/sandboxwich-entrypoint.sh");

    assert!(entrypoint.contains(
        "[[ ! -s \"${SANDBOXWICH_GUEST_TOKEN_FILE:-}\" && ! -s \"${SANDBOXWICH_API_TOKEN_FILE:-}\" ]]"
    ));
    assert!(entrypoint.contains("sandboxwich-agent daemon"));
}

#[test]
fn pod_adoption_preserves_original_guest_worker_binding_after_worker_restart() {
    let sandbox_id = SandboxId::new();
    let render = |worker_id| {
        let provider =
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_guest_credentials(
                    sandbox_id,
                    worker_id,
                    "http://sandboxwich-api.evalops.svc.cluster.local:3217",
                    "sbw_gtok_scoped",
                );
        provider
            .provision(
                sandbox_id,
                &SandboxProvisionSpec::default(),
                &CancelSignal::never_cancelled(),
            )
            .expect("dry-run provision should succeed")
            .metadata["manifests"]["pod"]
            .clone()
    };
    let desired = render(Uuid::new_v4());
    let observed = render(Uuid::new_v4());

    validate_adoption_contract(&desired, &observed)
        .expect("a replacement worker must adopt the original guest binding");

    let mut hostile = observed;
    let env = hostile["spec"]["containers"][0]["env"]
        .as_array_mut()
        .expect("pod env");
    env.iter_mut()
        .find(|entry| entry["name"] == "SANDBOXWICH_API")
        .expect("API env")["valueFrom"]["secretKeyRef"]["name"] = json!("attacker-secret");
    validate_adoption_contract(&desired, &hostile)
        .expect_err("unrelated guest environment drift must still block adoption");
}

#[test]
fn apply_manifests_carry_guest_token_only_in_the_secret_before_the_pod() {
    let sandbox_id = SandboxId::new();
    let dry_run =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_guest_credentials(
                sandbox_id,
                Uuid::nil(),
                "http://sandboxwich-api.evalops.svc.cluster.local:3217",
                "sbw_gtok_supersecret",
            );
    let provider = KubernetesApplyProvider::new(dry_run, "kubectl");
    let manifests = provider
        .provision_manifests(sandbox_id, &SandboxProvisionSpec::default())
        .unwrap();
    let secret_index = manifests
        .iter()
        .position(|manifest| manifest["kind"] == "Secret")
        .unwrap();
    let pod_index = manifests
        .iter()
        .position(|manifest| manifest["kind"] == "Pod")
        .unwrap();
    assert!(secret_index < pod_index);
    assert_eq!(
        manifests[secret_index]["stringData"]["api-token"],
        "sbw_gtok_supersecret"
    );
    assert_eq!(
        manifests
            .iter()
            .filter(|manifest| {
                serde_json::to_string(manifest)
                    .unwrap()
                    .contains("sbw_gtok_supersecret")
            })
            .count(),
        1
    );
    assert!(SANDBOX_TEARDOWN_RESOURCE_KINDS.contains("secret"));
}

#[test]
fn vnc_password_secret_is_mounted_as_a_read_only_file_not_an_env_var() {
    // The VNC password must be mounted as a file (mirroring the SSH
    // authorized-keys handling) rather than injected via
    // `secretKeyRef`: pod env vars are visible to anything that can
    // read this pod's spec through the Kubernetes API, not just the
    // process itself.
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_vnc_password_secret(Some("sandboxwich-vnc-password".to_string()));
    let provisioned = provider
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run provision should succeed");
    let pod = &provisioned.metadata["manifests"]["pod"];
    let env = pod["spec"]["containers"][0]["env"]
        .as_array()
        .expect("env should be an array");

    assert!(
        !env.iter()
            .any(|entry| entry["name"] == "SANDBOXWICH_VNC_PASSWORD"),
        "the raw VNC password must never be injected as a plain env var"
    );
    assert!(env.iter().any(|entry| {
        entry["name"] == "SANDBOXWICH_VNC_PASSWORD_FILE"
            && entry["value"] == "/run/sandboxwich/vnc/vnc-password"
    }));

    let volume_mounts = pod["spec"]["containers"][0]["volumeMounts"]
        .as_array()
        .expect("volumeMounts should be an array");
    assert!(volume_mounts.iter().any(|mount| {
        mount["name"] == "vnc-password"
            && mount["mountPath"] == "/run/sandboxwich/vnc"
            && mount["readOnly"] == true
    }));

    let volumes = pod["spec"]["volumes"]
        .as_array()
        .expect("volumes should be an array");
    assert!(volumes.iter().any(|volume| {
        volume["name"] == "vnc-password"
            && volume["secret"]["secretName"] == "sandboxwich-vnc-password"
            && volume["secret"]["items"][0]["key"] == "vnc-password"
            && volume["secret"]["items"][0]["path"] == "vnc-password"
    }));
}

#[test]
fn guest_manifests_never_receive_worker_credentials() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let sandbox_id = SandboxId::new();
    let child_id = SandboxId::new();
    let snapshot_id = SnapshotId::new();
    let provisioned = provider
        .provision(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run provision should succeed");
    let snapshot = provider
        .create_snapshot(sandbox_id, snapshot_id, &CancelSignal::never_cancelled())
        .expect("dry-run snapshot should succeed");
    let forked = provider
        .fork(
            sandbox_id,
            child_id,
            snapshot_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run fork should succeed");
    let apply = KubernetesApplyProvider::new(provider, "kubectl");
    let plan = apply.smoke_plan(sandbox_id, child_id, snapshot_id);
    let apply_manifests = apply
        .provision_manifests(sandbox_id, &SandboxProvisionSpec::default())
        .expect("apply manifests should render");

    for serialized in [
        serde_json::to_string(&provisioned).unwrap(),
        serde_json::to_string(&snapshot).unwrap(),
        serde_json::to_string(&forked).unwrap(),
        serde_json::to_string(&plan).unwrap(),
        serde_json::to_string(&apply_manifests).unwrap(),
    ] {
        assert!(!serialized.contains("SANDBOXWICH_API_TOKEN"));
        assert!(!serialized.contains("SANDBOXWICH_WORKER_ID"));
        assert!(!serialized.contains("worker-token"));
        assert!(!serialized.contains("workerTokenSecret"));
        assert!(!serialized.contains("sbw_wtok_"));
    }
}

#[test]
fn sandbox_namespace_override_places_all_sandbox_resources_in_dedicated_namespace() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich", None, None)
            .with_sandbox_namespace(Some("sandboxwich-sandboxes".to_string()));
    let provisioned = provider
        .provision(
            SandboxId::new(),
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run provision should succeed");

    assert_eq!(provisioned.metadata["namespace"], "sandboxwich-sandboxes");
    assert_eq!(provisioned.metadata["controlPlaneNamespace"], "sandboxwich");
    assert_eq!(
        provisioned.metadata["manifests"]["pod"]["metadata"]["namespace"],
        "sandboxwich-sandboxes"
    );
    assert_eq!(
        provisioned.metadata["manifests"]["networkPolicy"]["metadata"]["namespace"],
        "sandboxwich-sandboxes"
    );
    assert!(
        provisioned
            .resources
            .iter()
            .all(|resource| resource.namespace == "sandboxwich-sandboxes")
    );

    let apply = KubernetesApplyProvider::new(provider, "kubectl");
    let plan = apply.smoke_plan(SandboxId::new(), SandboxId::new(), SnapshotId::new());
    assert!(
        plan.apply_args
            .contains(&"sandboxwich-sandboxes".to_string())
    );
    assert!(!plan.apply_args.contains(&"sandboxwich".to_string()));
}

#[test]
fn teardown_args_delete_every_labeled_resource_kind_scoped_to_namespace() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let apply = KubernetesApplyProvider::new(provider, "kubectl")
        .with_kubectl_context(Some("k3s-ci".to_string()))
        .with_mutation_gate(true, true);
    let sandbox_id = SandboxId::new();

    let args = apply.teardown_args(sandbox_id);

    assert_eq!(
        args,
        vec![
            "--context".to_string(),
            "k3s-ci".to_string(),
            "-n".to_string(),
            "sandboxwich-ci".to_string(),
            "delete".to_string(),
            SANDBOX_TEARDOWN_RESOURCE_KINDS.to_string(),
            "-l".to_string(),
            format!("sandboxwich.dev/sandbox-id={sandbox_id}"),
            "--ignore-not-found=true".to_string(),
        ]
    );
}

#[test]
fn teardown_args_honor_persisted_gke_fqdn_resource_on_an_unconfigured_worker() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("gke-ci", "sandboxwich-ci", None, None);
    let apply = KubernetesApplyProvider::new(provider, "kubectl")
        .with_kubectl_context(Some("gke-ci".to_string()))
        .with_mutation_gate(true, true);

    let commands = apply.optional_teardown_args(
        SandboxId::new(),
        &SandboxTeardownSpec {
            delete_gke_fqdn_policy: true,
            ..SandboxTeardownSpec::default()
        },
    );

    assert_eq!(commands.len(), 1);
    assert!(commands[0].contains(&GKE_FQDN_RESOURCE_KIND.to_string()));
    assert!(!commands[0].contains(&SANDBOX_TEARDOWN_RESOURCE_KINDS.to_string()));
}

#[test]
fn teardown_deletes_the_cilium_policy_under_the_cilium_fqdn_backend() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_cilium_fqdn_egress(true);
    let apply = KubernetesApplyProvider::new(provider, "kubectl").with_mutation_gate(true, true);

    let commands = apply.optional_teardown_args(SandboxId::new(), &SandboxTeardownSpec::default());

    // `networkpolicy` does not match the CRD, so without this the policy that
    // is the enforcement boundary outlives the Sandbox it was rendered for.
    assert_eq!(commands.len(), 1);
    assert!(commands[0].contains(&CILIUM_FQDN_RESOURCE_KIND.to_string()));
}

#[test]
fn stop_deletes_core_resources_when_optional_gke_crd_is_absent() {
    let (kubectl, log_path) = write_fake_kubectl_missing_optional_resource();
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();

    provider
        .stop(
            sandbox_id,
            &SandboxTeardownSpec {
                delete_gke_fqdn_policy: true,
                ..SandboxTeardownSpec::default()
            },
            &CancelSignal::never_cancelled(),
        )
        .expect("an absent optional CRD must not fail core teardown");

    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    let core_delete = format!(
        "delete {SANDBOX_TEARDOWN_RESOURCE_KINDS} -l sandboxwich.dev/sandbox-id={sandbox_id}"
    );
    assert!(
        log.contains(&core_delete),
        "core teardown did not run: {log}"
    );
    assert!(
        log.contains(&format!("delete {GKE_FQDN_RESOURCE_KIND} -l")),
        "optional cleanup was not attempted separately: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn teardown_args_omit_context_flag_for_in_cluster_service_account() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let apply = KubernetesApplyProvider::new(provider, "kubectl")
        .with_kubectl_context(Some("in-cluster".to_string()))
        .with_mutation_gate(true, true);

    let args = apply.teardown_args(SandboxId::new());

    assert!(!args.iter().any(|arg| arg == "--context"));
    assert_eq!(args[0], "-n");
    assert!(args.contains(&SANDBOX_TEARDOWN_RESOURCE_KINDS.to_string()));
}

#[test]
fn stop_refuses_to_mutate_without_confirm_apply_gate() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let apply = KubernetesApplyProvider::new(provider, "kubectl");

    let error = apply
        .stop(
            SandboxId::new(),
            &SandboxTeardownSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("stop without the mutation gate should fail closed");
    assert!(error.to_string().contains("--confirm-apply"));
}

#[test]
fn dry_run_stop_is_a_successful_no_op() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);

    provider
        .stop(
            SandboxId::new(),
            &SandboxTeardownSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("dry-run stop should never fail");
}

#[test]
fn cap_output_bytes_passes_through_short_output_unchanged() {
    let text = "hello world";
    assert_eq!(cap_output_bytes(text.as_bytes(), 1024), text);
    // A cap exactly equal to the byte length is still "no truncation".
    assert_eq!(cap_output_bytes(text.as_bytes(), text.len() as u64), text);
}

#[test]
fn cap_output_bytes_truncates_and_marks_omitted_byte_count() {
    let text = "0123456789";
    let capped = cap_output_bytes(text.as_bytes(), 4);

    assert!(capped.starts_with("0123"));
    assert!(
        capped.contains("[truncated 6 bytes]"),
        "expected a marker noting the 6 omitted bytes, got: {capped:?}"
    );
}

/// Writes an executable fake `kubectl` script to a fresh temp directory,
/// returning `(script_path, log_path)`. The script:
/// - appends every invocation's space-joined argv as one line to `log_path`
///   (bracketed with leading/trailing spaces so tests can match whole
///   tokens like " delete " without false positives on substrings), and
/// - drains stdin for a successful "apply" verb, mirroring how
///   `run_kubectl_documents` actually pipes manifests in via stdin so the
///   real caller's `write_all` doesn't block on a full pipe;
/// - exits immediately with a non-zero status if `fail_verb` is present in
///   argv, including before draining stdin. This reproduces kubectl closing
///   its input early after an argument/authentication/validation failure.
///
/// This lets rollback behavior be exercised end-to-end (provision/fork
/// calling through to a real rollback `kubectl delete`) without requiring
/// a real cluster or kubectl binary.
fn write_fake_kubectl(fail_verb: Option<&'static str>) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("sandboxwich-fake-kubectl-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create fake kubectl temp dir");
    let log_path = dir.join("log.txt");
    let fail_check = match fail_verb {
        Some(verb) => format!("case \" $* \" in *\" {verb} \"*) exit 1 ;; esac\n"),
        None => String::new(),
    };
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             {fail_check}\
             case \" $* \" in\n\
             \x20\x20*\" apply \"*) cat >/dev/null 2>&1 || true ;;\n\
             \x20\x20*boundVolumeSnapshotContentName*)\n\
             \x20\x20  case \" $* \" in\n\
             \x20\x20  *\" get \"*) printf 'true|snapcontent-test|local-path-snapshot|' ;;\n\
             \x20\x20  esac\n\
             \x20\x20  ;;\n\
             \x20\x20*readyToUse*)\n\
             \x20\x20  case \" $* \" in\n\
             \x20\x20  *\" get \"*) printf 'true' ;;\n\
             \x20\x20  esac\n\
             \x20\x20  ;;\n\
             esac\n\
             exit 0\n",
        log = log_path.display(),
    );
    let script_path = dir.join("kubectl");
    std::fs::write(&script_path, script).expect("write fake kubectl script");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl script");
    }
    (script_path, log_path)
}

fn write_fake_kubectl_missing_optional_resource() -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-fake-kubectl-missing-crd-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create fake kubectl temp dir");
    let log_path = dir.join("log.txt");
    let script = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> \"{log}\"\n\
         case \" $* \" in\n\
         *\" {resource_kind} \"*)\n\
           echo 'error: the server doesn'\"'\"'t have a resource type \"fqdnnetworkpolicy\"' >&2\n\
           exit 1\n\
           ;;\n\
         esac\n\
         exit 0\n",
        log = log_path.display(),
        resource_kind = GKE_FQDN_RESOURCE_KIND,
    );
    let script_path = dir.join("kubectl");
    std::fs::write(&script_path, script).expect("write fake kubectl script");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl script");
    }
    (script_path, log_path)
}

fn apply_provider_with_fake_kubectl(kubectl: &std::path::Path) -> KubernetesApplyProvider {
    apply_provider_with_fake_kubectl_and_snapshot_class(kubectl, Some("local-path-snapshot"))
}

fn apply_provider_with_fake_kubectl_and_snapshot_class(
    kubectl: &std::path::Path,
    snapshot_class: Option<&str>,
) -> KubernetesApplyProvider {
    let dry_run = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        None,
        snapshot_class.map(str::to_string),
    );
    KubernetesApplyProvider::new(dry_run, kubectl.to_string_lossy().into_owned())
        .with_kubectl_context(Some("in-cluster".to_string()))
        .with_mutation_gate(true, true)
}

fn write_stateful_fake_kubectl() -> (std::path::PathBuf, std::path::PathBuf) {
    write_stateful_fake_kubectl_with_observed_runtime_class("")
}

/// Stateful fake kubectl whose live Pods report `observed_runtime_class` for
/// the provider's `spec.runtimeClassName` boundary read.
fn write_stateful_fake_kubectl_with_observed_runtime_class(
    observed_runtime_class: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir =
        std::env::temp_dir().join(format!("sandboxwich-stateful-kubectl-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create stateful fake kubectl dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{log}"
case " $* " in
  *runtimeClassName*) printf '%s' '{observed_runtime_class}' ;;
  *" get "*)
    python3 - "{dir}" "$@" <<'PY'
import json
import os
import sys
directory = sys.argv[1]
args = sys.argv[2:]
get_index = args.index("get")
resource_args = []
for arg in args[get_index + 1:]:
    if arg.startswith("-"):
        break
    resource_args.append(arg)
# Label/list form: `get volumesnapshot -l ...` has only a kind and no name.
# Stop's pre-delete snapshot wait uses that shape with a jsonpath that emits
# one name per line. This fake tracks objects by concrete name only, so an
# unlabeled inventory is empty stdout (zero names).
if len(resource_args) == 1 and "/" not in resource_args[0]:
    raise SystemExit(0)
requested_count = sum(1 for arg in resource_args if "/" in arg) or len(resource_args) // 2
resources = []
while resource_args:
    resource = resource_args.pop(0)
    if "/" in resource:
        kind, name = resource.split("/", 1)
    else:
        kind = resource
        name = resource_args.pop(0)
    marker = os.path.join(directory, kind.lower() + "-" + name)
    if not os.path.exists(marker):
        continue
    with open(marker, encoding="utf-8") as source:
        value = json.load(source)
    metadata = value.setdefault("metadata", {{}})
    metadata["uid"] = "uid-" + metadata["name"]
    metadata["generation"] = 1
    resources.append(value)
if requested_count == 1:
    if resources:
        print(json.dumps(resources[0]))
else:
    print(json.dumps({{"apiVersion": "v1", "kind": "List", "items": resources}}))
PY
    ;;
  *" apply "*)
    payload_file="{dir}/payload.$$"
    cat > "$payload_file"
    python3 - "{dir}" "{log}" "$payload_file" <<'PY'
import json
import os
import sys
directory, log, payload_file = sys.argv[1:]
with open(payload_file, encoding="utf-8") as source:
    documents = [json.loads(document) for document in source.read().split("\n---\n") if document.strip()]
with open(log, "a", encoding="utf-8") as output:
    output.write("DOCS " + " ".join(
        value["kind"] + "/" + value["metadata"]["name"] for value in documents
    ) + "\n")
for value in documents:
    marker = os.path.join(directory, value["kind"].lower() + "-" + value["metadata"]["name"])
    with open(marker, "w", encoding="utf-8") as output:
        json.dump(value, output)
PY
    rm -f "$payload_file"
    ;;
  *" wait "*) ;;
esac
"#,
        log = log_path.display(),
        dir = dir.display(),
        observed_runtime_class = observed_runtime_class,
    );
    std::fs::write(&script_path, script).expect("write stateful fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat stateful fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod stateful fake kubectl");
    }
    (script_path, log_path)
}

#[test]
fn provision_staged_keeps_post_ready_services_on_separate_authority_fences() {
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();

    provider
        .provision_staged(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
            |_| Ok(()),
        )
        .expect("staged provision succeeds");

    let log = std::fs::read_to_string(&log_path).expect("read staged kubectl log");
    assert_eq!(
        log.matches(" apply ").count(),
        5,
        "post-ready SSH and desktop Services must remain separate mutations: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn provision_staged_does_not_apply_desktop_service_after_ssh_report_rejection() {
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();

    let error = provider
        .provision_staged(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
            |report| {
                if report.stage == sandboxwich_core::ProvisioningStage::ServiceReady {
                    anyhow::bail!("lease authority moved before ServiceReady was accepted");
                }
                Ok(())
            },
        )
        .expect_err("the first rejected ServiceReady report must stop provisioning");
    assert!(
        error.to_string().contains("lease authority moved"),
        "the report rejection must remain the causal error: {error}"
    );

    let root = kubectl.parent().expect("fake kubectl parent");
    assert!(
        root.join(format!("service-sandboxwich-ssh-{sandbox_id}"))
            .exists(),
        "the SSH Service is applied before its readiness report"
    );
    assert!(
        !root
            .join(format!("service-sandboxwich-desktop-{sandbox_id}"))
            .exists(),
        "a rejected SSH readiness report must fence the later desktop Service mutation"
    );
    let log = std::fs::read_to_string(&log_path).expect("read staged kubectl log");
    assert!(
        !log.contains(" delete "),
        "report rejection means lease authority may have moved, so this worker must not roll back: {log}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn batched_service_preflight_rejects_conflicting_identity_before_apply() {
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();
    let ssh_service = provider.dry_run.ssh_service_manifest(sandbox_id);
    let desktop_service = provider.dry_run.desktop_service_manifest(sandbox_id);
    let mut conflicting = ssh_service.clone();
    conflicting["metadata"]["labels"]["sandboxwich.dev/sandbox-id"] =
        json!(SandboxId::new().to_string());
    let marker = kubectl
        .parent()
        .expect("fake kubectl parent")
        .join(format!("service-sandboxwich-ssh-{sandbox_id}"));
    std::fs::write(
        marker,
        serde_json::to_string(&conflicting).expect("serialize conflicting Service"),
    )
    .expect("seed conflicting Service");

    let mut resources_applied = false;
    let error = provider
        .apply_or_adopt_manifests_with_identity(
            &[&ssh_service, &desktop_service],
            "sandboxwich.dev/sandbox-id",
            &sandbox_id.to_string(),
            "sandbox",
            &CancelSignal::never_cancelled(),
            &mut resources_applied,
        )
        .expect_err("conflicting Service identity must fail closed");

    assert!(
        error.to_string().contains("conflicting sandbox identity"),
        "unexpected conflict error: {error:#}"
    );
    assert!(!resources_applied);
    let log = std::fs::read_to_string(&log_path).expect("read batched preflight log");
    assert!(
        !log.contains(" apply "),
        "identity conflict must be detected before mutation: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn provision_staged_applies_resources_in_durable_order_and_reports_uids() {
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();
    let mut reports = Vec::new();

    provider
        .provision_staged(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
            |report| {
                reports.push(report);
                Ok(())
            },
        )
        .expect("staged provision succeeds");

    let stages = reports
        .iter()
        .map(|report| report.stage.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        stages,
        vec![
            sandboxwich_core::ProvisioningStage::WorkspacePlanned,
            sandboxwich_core::ProvisioningStage::WorkspaceReady,
            sandboxwich_core::ProvisioningStage::NetworkPolicyReady,
            sandboxwich_core::ProvisioningStage::CredentialsReady,
            sandboxwich_core::ProvisioningStage::PodReady,
            sandboxwich_core::ProvisioningStage::ServiceReady,
            sandboxwich_core::ProvisioningStage::ServiceReady,
            sandboxwich_core::ProvisioningStage::SandboxReady,
        ]
    );
    assert!(
        reports
            .iter()
            .filter(|report| report.resource_name.is_some())
            .all(|report| report
                .resource_uid
                .as_deref()
                .is_some_and(|uid| uid.starts_with("uid-")))
    );

    let log = std::fs::read_to_string(&log_path).expect("read staged kubectl log");
    assert_eq!(
        log.matches(" get ").count(),
        10,
        "each authority-fenced stage must keep its own pre/post reads: {log}"
    );
    assert_eq!(
        log.matches(" apply ").count(),
        5,
        "workspace, network, pod, and both authority-fenced Services: {log}"
    );
    assert!(log.contains(" wait --for=condition=Ready "));

    let mut replay_reports = Vec::new();
    provider
        .provision_staged(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
            |report| {
                replay_reports.push(report);
                Ok(())
            },
        )
        .expect("matching resources are adopted on replay");
    let replay_log = std::fs::read_to_string(&log_path).expect("read replay kubectl log");
    assert_eq!(
        replay_log.matches(" apply ").count(),
        5,
        "replay must adopt the five existing resources: {replay_log}"
    );
    assert_eq!(replay_reports.len(), 8);

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn managed_home_is_adopted_by_replacement_runtime_and_survives_runtime_stop() {
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let home_id = HomeId::new();
    let first_sandbox_id = SandboxId::new();
    let replacement_sandbox_id = SandboxId::new();
    let spec = SandboxProvisionSpec::default();
    let cancelled = CancelSignal::never_cancelled();
    let mut report = |_| Ok(());

    provider
        .provision_home_staged(first_sandbox_id, home_id, &spec, &cancelled, &mut report)
        .expect("first runtime provisions its managed home");
    provider
        .stop(
            first_sandbox_id,
            &SandboxTeardownSpec::default(),
            &cancelled,
        )
        .expect("runtime stop succeeds without deleting the home");
    provider
        .provision_home_staged(
            replacement_sandbox_id,
            home_id,
            &spec,
            &cancelled,
            &mut report,
        )
        .expect("replacement runtime adopts the existing managed home");

    let log = std::fs::read_to_string(&log_path).expect("read managed-home kubectl log");
    assert_eq!(
        log.matches(" apply ").count(),
        9,
        "the replacement must adopt the home PVC and apply only its runtime resources: {log}"
    );
    assert!(
        log.contains(&format!(
            "delete pod,persistentvolumeclaim,service,networkpolicy,secret -l sandboxwich.dev/sandbox-id={first_sandbox_id}"
        )),
        "runtime cleanup must remain scoped to the sandbox identity: {log}"
    );
    assert!(
        !log.contains(&format!(
            "delete persistentvolumeclaim sandboxwich-home-{home_id}"
        )),
        "ordinary runtime cleanup must never delete the managed home: {log}"
    );

    let home_marker = kubectl
        .parent()
        .expect("fake kubectl parent")
        .join(format!("persistentvolumeclaim-sandboxwich-home-{home_id}"));
    let home_manifest =
        std::fs::read_to_string(home_marker).expect("managed home PVC remains present");
    assert!(home_manifest.contains(&format!(r#""sandboxwich.dev/home-id": "{home_id}""#)));
    assert!(!home_manifest.contains("sandboxwich.dev/sandbox-id"));

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn provision_staged_applies_the_guest_token_secret_before_the_pod() {
    // Regression: the staged provisioning path used to report
    // CredentialsReady without applying the guest-token Secret at all, so
    // the pod (whose spec mounts that Secret whenever guest credentials
    // exist) sat in FailedMount until the ready-wait timed out.
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let sandbox_id = SandboxId::new();
    let dry_run =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_guest_credentials(
                sandbox_id,
                Uuid::nil(),
                "http://sandboxwich-api.evalops.svc.cluster.local:3217",
                "sbw_gtok_supersecret",
            );
    let provider = KubernetesApplyProvider::new(dry_run, kubectl.to_string_lossy().into_owned())
        .with_kubectl_context(Some("in-cluster".to_string()))
        .with_mutation_gate(true, true);
    let mut reports = Vec::new();

    provider
        .provision_staged(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
            |report| {
                reports.push(report);
                Ok(())
            },
        )
        .expect("staged provision succeeds");

    let credentials_index = reports
        .iter()
        .position(|report| report.stage == sandboxwich_core::ProvisioningStage::CredentialsReady)
        .expect("CredentialsReady stage is reported");
    assert_eq!(
        reports[credentials_index].resource_name.as_deref(),
        Some(format!("sandboxwich-guest-token-{sandbox_id}").as_str()),
        "CredentialsReady must carry the applied Secret's identity"
    );
    let pod_index = reports
        .iter()
        .position(|report| report.stage == sandboxwich_core::ProvisioningStage::PodReady)
        .expect("PodReady stage is reported");
    assert!(
        credentials_index < pod_index,
        "the Secret must be applied before the pod that mounts it"
    );

    // The stateful fake kubectl records every applied manifest as a
    // `<kind>-<name>` marker file; the Secret's marker proves the staged
    // path actually applied it rather than only reporting the stage.
    let secret_marker = kubectl
        .parent()
        .expect("fake kubectl parent")
        .join(format!("secret-sandboxwich-guest-token-{sandbox_id}"));
    let secret_payload =
        std::fs::read_to_string(&secret_marker).expect("guest-token Secret was applied");
    assert!(secret_payload.contains("sbw_gtok_supersecret"));

    let log = std::fs::read_to_string(&log_path).expect("read staged kubectl log");
    assert_eq!(
        log.matches(" apply ").count(),
        6,
        "workspace, secret, policy, pod, and both authority-fenced Services: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn provision_staged_reports_the_actual_sterile_maestro_pod_identity() {
    let (kubectl, _) = write_stateful_fake_kubectl();
    let sandbox_id = SandboxId::new();
    let candidate = sterile_maestro_candidate(sandbox_id);
    let dry_run =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_runtime_class_name(Some("kata".to_string()))
            .with_guest_credentials(
                sandbox_id,
                Uuid::now_v7(),
                "http://sandboxwich-api.evalops.svc.cluster.local:3217",
                "sbw_gtok_sterile_candidate",
            );
    let provider = KubernetesApplyProvider::new(dry_run, kubectl.to_string_lossy().into_owned())
        .with_kubectl_context(Some("in-cluster".to_string()))
        .with_mutation_gate(true, true);
    let spec = SandboxProvisionSpec {
        workspace_mode: WorkspaceMode::Persistent,
        sterile_pool_candidate: Some(candidate.clone()),
        ..SandboxProvisionSpec::default()
    };
    let mut reports = Vec::new();

    let handle = provider
        .provision_staged(
            sandbox_id,
            &spec,
            &CancelSignal::never_cancelled(),
            |report| {
                reports.push(report);
                Ok(())
            },
        )
        .expect("staged sterile candidate provision succeeds");

    let pod = reports
        .iter()
        .find(|report| report.stage == ProvisioningStage::PodReady)
        .expect("PodReady report");
    assert_eq!(
        pod.resource_name.as_deref(),
        Some(format!("sandboxwich-{sandbox_id}").as_str())
    );
    assert!(
        pod.resource_uid
            .as_deref()
            .is_some_and(|uid| uid.starts_with("uid-"))
    );
    assert!(pod.observed_generation.is_some());
    assert!(handle.resources.iter().any(|resource| {
        resource.resource_kind == RuntimeResourceKind::Service
            && resource.resource_name == candidate.service_name
            && resource.service_port == Some(MAESTRO_HOSTED_RUNNER_CONTAINER_PORT)
    }));
    assert!(handle.resources.iter().all(|resource| {
        !matches!(
            resource.purpose,
            RuntimeResourcePurpose::Ssh | RuntimeResourcePurpose::Desktop
        )
    }));

    let supervisor_marker = kubectl
        .parent()
        .unwrap()
        .join(format!("pod-sandboxwich-supervisor-{sandbox_id}"));
    let supervisor: Value = serde_json::from_str(
        &std::fs::read_to_string(supervisor_marker).expect("supervisor Pod was applied"),
    )
    .unwrap();
    let env = supervisor["spec"]["containers"][0]["env"]
        .as_array()
        .unwrap();
    let env_value = |name: &str| {
        env.iter()
            .find(|entry| entry["name"] == name)
            .and_then(|entry| entry["value"].as_str())
            .unwrap()
    };
    assert_eq!(
        env_value("SANDBOXWICH_PROVIDER_POD_NAME"),
        format!("sandboxwich-{sandbox_id}")
    );
    assert_eq!(
        env_value("SANDBOXWICH_PROVIDER_POD_UID"),
        format!("uid-sandboxwich-{sandbox_id}")
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn provision_staged_adopts_candidate_pki_after_lost_response_without_secret_drift() {
    let (kubectl, _) = write_stateful_fake_kubectl();
    let sandbox_id = SandboxId::new();
    let candidate = sterile_maestro_candidate(sandbox_id);
    let spec = SandboxProvisionSpec {
        workspace_mode: WorkspaceMode::Persistent,
        sterile_pool_candidate: Some(candidate),
        ..SandboxProvisionSpec::default()
    };
    let make_provider = |worker_id| {
        KubernetesApplyProvider::new(
            KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
                .with_runtime_class_name(Some("kata".to_string()))
                .with_guest_credentials(
                    sandbox_id,
                    worker_id,
                    "http://sandboxwich-api.evalops.svc.cluster.local:3217",
                    format!("sbw_gtok_{worker_id}"),
                ),
            kubectl.to_string_lossy().into_owned(),
        )
        .with_kubectl_context(Some("in-cluster".to_string()))
        .with_mutation_gate(true, true)
    };
    make_provider(Uuid::now_v7())
        .provision_staged(sandbox_id, &spec, &CancelSignal::never_cancelled(), |_| {
            Ok(())
        })
        .expect("initial candidate provision");
    let client_marker = kubectl
        .parent()
        .unwrap()
        .join(format!("secret-sandboxwich-activation-client-{sandbox_id}"));
    let server_marker = kubectl
        .parent()
        .unwrap()
        .join(format!("secret-sandboxwich-activation-server-{sandbox_id}"));
    let client_before = std::fs::read(&client_marker).unwrap();
    let server_before = std::fs::read(&server_marker).unwrap();
    std::fs::remove_file(&server_marker)
        .expect("simulate response loss after client/CA creation but before server observation");

    make_provider(Uuid::now_v7())
        .provision_staged(sandbox_id, &spec, &CancelSignal::never_cancelled(), |_| {
            Ok(())
        })
        .expect("lost-response retry adopts the existing candidate boundary");
    assert_eq!(std::fs::read(client_marker).unwrap(), client_before);
    let server_after = std::fs::read(server_marker).unwrap();
    assert_ne!(server_after, server_before);
    let client: Value = serde_json::from_slice(&client_before).unwrap();
    let server: Value = serde_json::from_slice(&server_after).unwrap();
    assert_eq!(
        client["stringData"]["ca.crt"],
        server["stringData"]["ca.crt"]
    );
    validate_activation_tls_secret(&client).unwrap();
    validate_activation_tls_secret(&server).unwrap();

    let _ = std::fs::remove_dir_all(kubectl.parent().unwrap());
}

#[test]
fn provision_staged_starts_runtime_before_waiting_for_gateway() {
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let dry_run =
        KubernetesDryRunProvider::with_snapshot_class("gke-ci", "sandboxwich-ci", None, None)
            .with_egress_gateway_image(Some(format!(
                "ghcr.io/evalops/sandboxwich-worker@sha256:{}",
                "a".repeat(64)
            )));
    let provider = KubernetesApplyProvider::new(dry_run, kubectl.to_string_lossy().into_owned())
        .with_mutation_gate(true, true);
    let sandbox_id = SandboxId::new();
    let spec = SandboxProvisionSpec {
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }],
        },
        ..SandboxProvisionSpec::default()
    };
    let handle = provider
        .provision_staged(sandbox_id, &spec, &CancelSignal::never_cancelled(), |_| {
            Ok(())
        })
        .expect("gateway provision succeeds");
    let log = std::fs::read_to_string(&log_path).expect("read staged kubectl log");
    let gateway_wait = log
        .find(&format!("pod/sandboxwich-egress-gateway-{sandbox_id}"))
        .expect("gateway readiness wait");
    let runtime_start = log
        .find(&format!("get Pod sandboxwich-{sandbox_id}"))
        .expect("runtime start");
    assert!(
        runtime_start < gateway_wait,
        "runtime and gateway cold starts must overlap before readiness waits: {log}"
    );
    assert_eq!(
        log.matches(" get ").count(),
        12,
        "the host-egress network wave must share one pre-apply and one post-apply read: {log}"
    );
    assert_eq!(
        log.matches(" apply ").count(),
        6,
        "gateway Service, Pod, and base policy must share their report-free apply: {log}"
    );
    assert!(handle.resources.iter().any(|resource| {
        resource.resource_kind == sandboxwich_core::RuntimeResourceKind::Pod
            && resource.resource_name == format!("sandboxwich-egress-gateway-{sandbox_id}")
    }));

    // Historical GKE resources remain discoverable for cleanup after the
    // backend is removed from new provisions.
    let fqdn_observed = ObservedKubernetesResource {
        sandbox_id: Some(sandbox_id),
        resource_kind: sandboxwich_core::RuntimeResourceKind::NetworkPolicy,
        namespace: "sandboxwich-ci".to_string(),
        name: format!("sandboxwich-fqdn-egress-{sandbox_id}"),
        uid: "uid-fqdn".to_string(),
        resident_lease_id: None,
        created_at: None,
        volume_claim_phase: None,
    };
    assert_eq!(
        kubernetes_delete_path(&fqdn_observed).expect("GKE FQDN delete path"),
        format!(
            "/apis/networking.gke.io/v1alpha1/namespaces/sandboxwich-ci/fqdnnetworkpolicies/sandboxwich-fqdn-egress-{sandbox_id}"
        )
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn provision_staged_stops_before_the_next_resource_when_reporting_fails() {
    let (kubectl, log_path) = write_stateful_fake_kubectl();
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();
    let error = provider
        .provision_staged(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
            |report| {
                if report.stage == sandboxwich_core::ProvisioningStage::NetworkPolicyReady {
                    anyhow::bail!("lost provisioning lease")
                }
                Ok(())
            },
        )
        .expect_err("reporting failure stops staged provisioning");
    assert!(
        error.to_string().contains("lost provisioning lease"),
        "unexpected staged provision error: {error:#}"
    );

    let log = std::fs::read_to_string(&log_path).expect("read failed-report kubectl log");
    assert_eq!(
        log.matches(" apply ").count(),
        2,
        "workspace and network policy apply before their durable reports: {log}"
    );
    assert!(!log.contains(" wait "), "pod stage must not start: {log}");
    // A rejected stage update is the control plane refusing this attempt's
    // authority, and it can arrive before the renewal loop fires the cancel
    // signal. Deleting by sandbox-id label could then destroy resources a new
    // lease owner already applied, so residue from this path is left to the
    // unbound-workspace-claim backstop instead.
    assert!(
        !log.contains(" delete "),
        "a rejected stage update must not trigger rollback: {log}"
    );
    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn guest_token_secret_adoption_accepts_rotated_token_but_rejects_api_url_drift() {
    // Regression for the chaos lost-response replay: every provisioning
    // attempt mints a fresh guest token, so a replayed provision's desired
    // Secret can never byte-match the token the live Secret holds. Adoption
    // must accept that rotation (presence of `api-token`, not equality) but
    // still refuse a Secret whose `api-url` points somewhere else, and still
    // require the token key to exist at all.
    let sandbox_id = SandboxId::new();
    let render = |token: &str, api: &str| {
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_guest_credentials(sandbox_id, Uuid::nil(), api, token)
            .guest_token_secret_manifest(sandbox_id)
            .expect("credentials render a guest-token secret")
    };
    let api = "http://sandboxwich-api.evalops.svc.cluster.local:3217";
    let desired = render("sbw_gtok_attempt_two", api);

    let existing_with_rotated_token = render("sbw_gtok_attempt_one", api);
    validate_adoption_contract(&desired, &existing_with_rotated_token)
        .expect("a rotated api-token value must not block adoption");

    let existing_with_hostile_api = render("sbw_gtok_attempt_one", "http://attacker.example:3217");
    validate_adoption_contract(&desired, &existing_with_hostile_api)
        .expect_err("an api-url pointing at a different control plane must block adoption");

    let mut existing_without_token = render("sbw_gtok_attempt_one", api);
    existing_without_token["stringData"]
        .as_object_mut()
        .expect("stringData object")
        .remove("api-token");
    validate_adoption_contract(&desired, &existing_without_token)
        .expect_err("a guest-token Secret without an api-token key must block adoption");
}

#[test]
fn adoption_contract_rejects_immutable_or_security_drift_for_every_resource_kind() {
    let provider = KubernetesDryRunProvider::with_snapshot_class(
        "k3s-ci",
        "sandboxwich-ci",
        Some("local-path".to_string()),
        None,
    );
    let sandbox_id = SandboxId::new();
    let spec = SandboxProvisionSpec::default();
    let pvc = provider.pvc_manifest(
        format!("sandboxwich-pvc-{sandbox_id}"),
        Some(sandbox_id),
        &spec.memory_limit,
    );
    let network_policy = provider
        .network_policy_manifest(sandbox_id, &spec.network_egress)
        .expect("render network policy");
    let pod = provider.pod_manifest(sandbox_id, &spec);
    let service = provider.ssh_service_manifest(sandbox_id);
    let secret = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": format!("sandboxwich-secret-{sandbox_id}"),
            "namespace": "sandboxwich-ci",
            "labels": { "sandboxwich.dev/sandbox-id": sandbox_id.to_string() }
        },
        "type": "Opaque",
        "immutable": true,
        "data": { "token": "cmVkYWN0ZWQ=" }
    });

    for desired in [&pvc, &network_policy, &pod, &service, &secret] {
        validate_adoption_contract(desired, desired).expect("identical resource is adoptable");
    }

    let mut defaulted_pod = pod.clone();
    defaulted_pod["spec"]["restartPolicy"] = json!("Always");
    defaulted_pod["spec"]["dnsPolicy"] = json!("ClusterFirst");
    defaulted_pod["spec"]["containers"][0]["terminationMessagePath"] =
        json!("/dev/termination-log");
    defaulted_pod["spec"]["containers"][0]["terminationMessagePolicy"] = json!("File");
    validate_adoption_contract(&pod, &defaulted_pod)
        .expect("Kubernetes API defaults do not change the desired pod contract");

    for field in ["hostNetwork", "hostPID", "hostIPC"] {
        let mut hostile_pod = pod.clone();
        hostile_pod["spec"][field] = json!(true);
        let error = validate_adoption_contract(&pod, &hostile_pod)
            .expect_err("host namespace escalation must block pod adoption");
        let provider_error = error
            .downcast_ref::<ProviderError>()
            .expect("host namespace conflict is typed");
        assert_eq!(
            provider_error.error_class(),
            sandboxwich_core::ProvisioningErrorClass::TerminalSecurity,
            "unexpected class for {field}"
        );
    }

    let mut defaulted_network_policy = network_policy.clone();
    if let Some(first_port) = defaulted_network_policy["spec"]["ingress"][0]["ports"]
        .as_array_mut()
        .and_then(|ports| ports.first_mut())
    {
        first_port["protocol"] = json!("TCP");
    }
    validate_adoption_contract(&network_policy, &defaulted_network_policy)
        .expect("defaulted network policy protocol is semantically equivalent");

    let mut api_normalized_deny_all_policy = network_policy.clone();
    api_normalized_deny_all_policy["spec"]
        .as_object_mut()
        .expect("network policy spec")
        .remove("egress");
    validate_adoption_contract(&network_policy, &api_normalized_deny_all_policy)
        .expect_err("omitting invariant DNS and API egress must block adoption");

    let mut changed_pvc = pvc.clone();
    changed_pvc["spec"]["storageClassName"] = json!("wrong-storage-class");
    let mut changed_network_policy = network_policy.clone();
    changed_network_policy["spec"]["egress"] = json!([{}]);
    let mut changed_pod = pod.clone();
    changed_pod["spec"]["containers"][0]["image"] = json!("attacker.invalid/image:latest");
    let mut changed_service = service.clone();
    changed_service["spec"]["ports"][0]["targetPort"] = json!(22);
    let mut changed_secret = secret.clone();
    changed_secret["data"]["token"] = json!("YXR0YWNrZXI=");

    for (desired, changed) in [
        (&pvc, &changed_pvc),
        (&network_policy, &changed_network_policy),
        (&pod, &changed_pod),
        (&service, &changed_service),
        (&secret, &changed_secret),
    ] {
        let error = validate_adoption_contract(desired, changed)
            .expect_err("drifted resource must not be adopted");
        let provider_error = error
            .downcast_ref::<ProviderError>()
            .expect("adoption conflict is typed");
        assert!(matches!(
            provider_error.error_class(),
            sandboxwich_core::ProvisioningErrorClass::TerminalContract
                | sandboxwich_core::ProvisioningErrorClass::TerminalSecurity
        ));
    }
}

#[test]
fn kubectl_failures_map_to_typed_provisioning_error_classes() {
    for (stderr, expected_class, expected_reason) in [
        (
            "0/2 nodes are available: pod has unbound immediate PersistentVolumeClaims",
            sandboxwich_core::ProvisioningErrorClass::RetryableCapacity,
            "workspace_capacity_pending",
        ),
        (
            "admission webhook denied the request: violates PodSecurity restricted",
            sandboxwich_core::ProvisioningErrorClass::TerminalSecurity,
            "kubernetes_policy_denied",
        ),
        (
            "The Pod is invalid: spec.containers: Required value",
            sandboxwich_core::ProvisioningErrorClass::TerminalContract,
            "kubernetes_contract_invalid",
        ),
        (
            "Unable to connect to the server: i/o timeout",
            sandboxwich_core::ProvisioningErrorClass::RetryableProvider,
            "kubernetes_provider_transient",
        ),
    ] {
        let error = classified_kubectl_failure("provision stage", stderr);
        assert_eq!(error.error_class(), expected_class);
        assert_eq!(error.reason_code(), expected_reason);
    }
}

/// A ResourceQuota rejection is capacity pressure, not a security verdict.
///
/// The API server phrases quota rejections with the same "(Forbidden)" prefix it
/// uses for RBAC denials, so the `forbidden` arm of
/// [`classified_kubectl_failure`] used to claim them first and return
/// `TerminalSecurity`, whose disposition is `RetryDisposition::Permanent`. Every
/// provision that lost a quota race then died on attempt 1 instead of waiting
/// for a peer sandbox to release its slot: 1,285 provisions failed that way in a
/// three-hour window on 2026-08-02.
#[test]
fn resource_quota_rejections_are_retryable_capacity_not_terminal_security() {
    let stderr = "Error from server (Forbidden): error when creating \"STDIN\": \
pods \"sandbox-6f2a\" is forbidden: exceeded quota: sandbox-capacity, \
requested: pods=1, used: pods=4, limited: pods=4";

    let error = classified_kubectl_failure("provision stage", stderr);

    assert_eq!(
        error.error_class(),
        sandboxwich_core::ProvisioningErrorClass::RetryableCapacity,
    );
    assert_eq!(error.reason_code(), "workspace_capacity_pending");
    assert_eq!(error.disposition(), RetryDisposition::Retryable);
}

/// The control for the test above: a genuine RBAC denial carries no quota text
/// and must still be terminal, so a misconfigured ServiceAccount is not retried
/// against the cluster forever.
#[test]
fn rbac_forbidden_still_classifies_as_terminal_security() {
    let stderr = "Error from server (Forbidden): pods is forbidden: User \
\"system:serviceaccount:sandboxwich:worker\" cannot create resource \"pods\" \
in API group \"\" in the namespace \"sandboxwich\"";

    let error = classified_kubectl_failure("provision stage", stderr);

    assert_eq!(
        error.error_class(),
        sandboxwich_core::ProvisioningErrorClass::TerminalSecurity,
    );
    assert_eq!(error.reason_code(), "kubernetes_policy_denied");
    assert_eq!(error.disposition(), RetryDisposition::Permanent);
}

#[test]
fn unschedulable_pod_is_terminal_rather_than_a_readiness_timeout() {
    // The scheduler text a 4Gi sandbox gets against a pool whose nodes cannot
    // offer 4Gi. `kubectl wait` reports only "timed out waiting for the
    // condition" for this, which classifies as retryable and is retried forever.
    let pod = serde_json::json!({
        "status": {
            "conditions": [
                {"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
                 "message": "0/15 nodes are available: 3 Insufficient cpu, 3 Insufficient memory, 4 node(s) had untolerated taint(s)."}
            ]
        }
    });

    let error = unschedulable_pod_failure("sandbox pod did not become ready", &pod)
        .expect("an unschedulable pod is classified");
    assert_eq!(
        error.error_class(),
        sandboxwich_core::ProvisioningErrorClass::TerminalContract
    );
    assert_eq!(error.reason_code(), "pod_unschedulable");
    // The scheduler's per-node breakdown has to survive into the message, since
    // it is the only place the reason is recorded.
    assert!(
        format!("{error:#}").contains("Insufficient memory"),
        "scheduler detail must reach the operator: {error:#}"
    );
}

#[test]
fn pods_not_blocked_on_scheduling_fall_back_to_stderr_classification() {
    // A Pod that scheduled and is merely slow to start must not be reported as
    // unschedulable; the caller falls back to classifying the kubectl stderr.
    let scheduled = serde_json::json!({
        "status": {
            "conditions": [{"type": "PodScheduled", "status": "True"}]
        }
    });
    assert!(unschedulable_pod_failure("ctx", &scheduled).is_none());

    // Blocked on scheduling, but for a reason the scheduler does not call
    // Unschedulable -- left to the existing classifier rather than guessed at.
    let other_reason = serde_json::json!({
        "status": {
            "conditions": [
                {"type": "PodScheduled", "status": "False", "reason": "SchedulerError",
                 "message": "internal error"}
            ]
        }
    });
    assert!(unschedulable_pod_failure("ctx", &other_reason).is_none());

    // No status at all, e.g. a Pod object read mid-creation.
    assert!(unschedulable_pod_failure("ctx", &serde_json::json!({})).is_none());
}

/// Fake kubectl for the scheduling-diagnosis path. `mode` selects what
/// `kubectl get pod -o json` does, so the caller can exercise the unschedulable
/// verdict and both fallback routes.
fn write_scheduling_fake_kubectl(mode: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-scheduling-kubectl-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create scheduling fake kubectl dir");
    let script_path = dir.join("kubectl");
    let body = match mode {
        "unschedulable" => {
            r#"printf '%s\n' '{"status":{"conditions":[{"type":"PodScheduled","status":"False","reason":"Unschedulable","message":"0/15 nodes are available: 3 Insufficient cpu, 3 Insufficient memory, 4 node(s) had untolerated taint(s)."}]}}'"#
        }
        "scheduled" => {
            r#"printf '%s\n' '{"status":{"conditions":[{"type":"PodScheduled","status":"True"}]}}'"#
        }
        "invalid_json" => r#"printf '%s\n' 'not json at all'"#,
        "get_fails" => r#"echo 'Error from server (NotFound): pods "x" not found' >&2; exit 1"#,
        other => panic!("unknown scheduling fake kubectl mode {other}"),
    };
    let script = format!("#!/bin/sh\n{body}\n");
    std::fs::write(&script_path, script).expect("write scheduling fake kubectl");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat scheduling fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod scheduling fake kubectl");
    }
    script_path
}

fn scheduling_provider(kubectl: &std::path::Path) -> KubernetesApplyProvider {
    KubernetesApplyProvider::new(
        KubernetesDryRunProvider::with_snapshot_class("in-cluster", "sandboxwich-ci", None, None),
        kubectl.to_string_lossy().into_owned(),
    )
}

#[test]
fn scheduling_failure_reports_the_scheduler_verdict_through_kubectl() {
    // The wiring, not just the classifier: shells out to kubectl, parses the
    // Pod, and returns the terminal error with the scheduler's breakdown.
    let kubectl = write_scheduling_fake_kubectl("unschedulable");
    let provider = scheduling_provider(&kubectl);

    let error = provider
        .scheduling_failure(
            "sandbox-pod",
            "sandbox pod did not become ready",
            &CancelSignal::never_cancelled(),
        )
        .expect("an unschedulable pod is diagnosed through kubectl");

    assert_eq!(
        error.error_class(),
        sandboxwich_core::ProvisioningErrorClass::TerminalContract
    );
    assert_eq!(error.reason_code(), "pod_unschedulable");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("Insufficient memory"), "{rendered}");
    assert!(
        rendered.contains("sandbox pod did not become ready"),
        "{rendered}"
    );
}

#[test]
fn scheduling_diagnosis_never_becomes_a_new_failure_mode() {
    // Every route that cannot produce a confident verdict must return None so
    // the caller falls back to classifying the kubectl stderr as before. A
    // diagnosis step that could itself fail would be worse than the bug.
    for mode in ["scheduled", "invalid_json", "get_fails"] {
        let kubectl = write_scheduling_fake_kubectl(mode);
        let provider = scheduling_provider(&kubectl);
        assert!(
            provider
                .scheduling_failure(
                    "sandbox-pod",
                    "sandbox pod did not become ready",
                    &CancelSignal::never_cancelled(),
                )
                .is_none(),
            "mode {mode} must fall back rather than classify"
        );
    }
}

#[test]
fn unschedulable_classification_is_terminal_so_the_retry_loop_stops() {
    // The whole point of the fix: this class must not be retryable, or the
    // sandbox goes back round the loop against a cluster that cannot place it.
    let pod = serde_json::json!({
        "status": {"conditions": [
            {"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
             "message": "0/3 nodes are available: 3 Insufficient memory."}
        ]}
    });
    let error = unschedulable_pod_failure("ctx", &pod).expect("classified");
    assert_eq!(error.disposition(), RetryDisposition::Permanent);
}

#[test]
fn orphan_reconciliation_classifies_expected_orphaned_expired_and_indeterminate() {
    let now = Utc::now();
    let live_sandbox = SandboxId::new();
    let expired_sandbox = SandboxId::new();
    let orphan_sandbox = SandboxId::new();
    let inventory = ReconciliationInventory {
        sandbox_ids: std::collections::HashSet::from([live_sandbox, expired_sandbox]),
        active_resident_lease_ids: std::collections::HashSet::new(),
        resources: vec![ExpectedKubernetesResource {
            sandbox_id: live_sandbox,
            resource_kind: RuntimeResourceKind::Pod,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-{live_sandbox}"),
            uid: "uid-live".to_string(),
            expires_at: Some(now + chrono::Duration::minutes(5)),
        }],
    };
    let observed = vec![
        ObservedKubernetesResource {
            sandbox_id: Some(live_sandbox),
            resource_kind: RuntimeResourceKind::Pod,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-{live_sandbox}"),
            uid: "uid-live".to_string(),
            resident_lease_id: None,
            created_at: None,
            volume_claim_phase: None,
        },
        ObservedKubernetesResource {
            sandbox_id: Some(orphan_sandbox),
            resource_kind: RuntimeResourceKind::Service,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-{orphan_sandbox}"),
            uid: "uid-orphan".to_string(),
            resident_lease_id: None,
            created_at: None,
            volume_claim_phase: None,
        },
        ObservedKubernetesResource {
            sandbox_id: Some(expired_sandbox),
            resource_kind: RuntimeResourceKind::PersistentVolumeClaim,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-pvc-{expired_sandbox}"),
            uid: "uid-expired".to_string(),
            resident_lease_id: None,
            created_at: None,
            volume_claim_phase: None,
        },
        ObservedKubernetesResource {
            sandbox_id: None,
            resource_kind: RuntimeResourceKind::Pod,
            namespace: "sandboxwich-ci".to_string(),
            name: "foreign-pod".to_string(),
            uid: "uid-foreign".to_string(),
            resident_lease_id: None,
            created_at: None,
            volume_claim_phase: None,
        },
        ObservedKubernetesResource {
            sandbox_id: Some(live_sandbox),
            resource_kind: RuntimeResourceKind::Pod,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-{live_sandbox}"),
            uid: "replacement-uid".to_string(),
            resident_lease_id: None,
            created_at: None,
            volume_claim_phase: None,
        },
    ];
    let expired =
        std::collections::HashMap::from([(expired_sandbox, now - chrono::Duration::seconds(1))]);

    let decisions = classify_reconciliation(&inventory, &observed, &expired, now);
    assert_eq!(
        decisions[0].classification,
        ReconciliationClassification::Expected
    );
    assert_eq!(
        decisions[1].classification,
        ReconciliationClassification::Orphaned
    );
    assert_eq!(
        decisions[2].classification,
        ReconciliationClassification::Expired
    );
    assert_eq!(
        decisions[3].classification,
        ReconciliationClassification::Indeterminate
    );
    assert!(!decisions[3].delete_allowed);
    assert_eq!(
        decisions[4].classification,
        ReconciliationClassification::Indeterminate
    );
    assert!(!decisions[4].delete_allowed);

    let unavailable = plan_orphan_reconciliation(
        Err(anyhow::anyhow!("database unavailable")),
        &observed,
        &expired,
        now,
    );
    assert!(unavailable.iter().all(|decision| {
        decision.classification == ReconciliationClassification::Indeterminate
            && !decision.delete_allowed
    }));
}

#[test]
fn resident_resource_reconciliation_is_fenced_by_active_lease_not_live_sandbox() {
    let sandbox_id = SandboxId::new();
    let active_lease = Uuid::new_v4();
    let stale_lease = Uuid::new_v4();
    let newly_claimed_lease = Uuid::new_v4();
    let inventory = ReconciliationInventory {
        sandbox_ids: std::collections::HashSet::from([sandbox_id]),
        resources: Vec::new(),
        active_resident_lease_ids: std::collections::HashSet::from([active_lease]),
    };
    let now = Utc::now();
    let resource = |lease_id, created_at| ObservedKubernetesResource {
        sandbox_id: Some(sandbox_id),
        resource_kind: RuntimeResourceKind::Pod,
        namespace: "sandboxwich-ci".to_string(),
        name: format!("resident-{lease_id}"),
        uid: format!("uid-{lease_id}"),
        resident_lease_id: Some(lease_id),
        created_at: Some(created_at),
        volume_claim_phase: None,
    };
    let decisions = classify_reconciliation(
        &inventory,
        &[
            resource(active_lease, now),
            resource(stale_lease, now - chrono::Duration::minutes(6)),
            resource(newly_claimed_lease, now),
        ],
        &std::collections::HashMap::new(),
        now,
    );
    assert_eq!(
        decisions[0].classification,
        ReconciliationClassification::Expected
    );
    assert!(!decisions[0].delete_allowed);
    assert_eq!(
        decisions[1].classification,
        ReconciliationClassification::Orphaned
    );
    assert!(decisions[1].delete_allowed);
    assert_eq!(
        decisions[2].classification,
        ReconciliationClassification::Indeterminate
    );
    assert!(!decisions[2].delete_allowed);
}

#[test]
fn orphan_reconciliation_parses_compact_resource_inventory_rows() {
    let sandbox_id = SandboxId::new();
    let lease_id = Uuid::new_v4();
    let rows = format!(
        "NetworkPolicy {sandbox_id} sandboxwich-ci sandboxwich-egress-{sandbox_id} uid-policy {lease_id} 2026-08-03T08:26:50Z <none>\n\
PersistentVolumeClaim {sandbox_id} sandboxwich-ci sandboxwich-pvc-{sandbox_id} uid-pvc <none> 2026-08-03T08:26:50Z Bound\n"
    );

    let resources = parse_reconciliation_resource_rows(&rows).expect("parse compact inventory");
    assert_eq!(resources.len(), 2);
    assert_eq!(
        resources[0].resource_kind,
        RuntimeResourceKind::NetworkPolicy
    );
    assert_eq!(resources[0].sandbox_id, Some(sandbox_id));
    assert_eq!(resources[0].resident_lease_id, Some(lease_id));
    assert_eq!(resources[0].volume_claim_phase, None);
    assert_eq!(
        resources[1].resource_kind,
        RuntimeResourceKind::PersistentVolumeClaim
    );
    assert_eq!(resources[1].resident_lease_id, None);
    assert_eq!(
        resources[1].volume_claim_phase,
        Some(VolumeClaimPhase::Bound)
    );
}

#[test]
fn orphan_reconciliation_discovery_has_a_separate_timeout_bound() {
    assert_eq!(
        orphan_reconciliation_discovery_timeout(Duration::from_secs(900)),
        Duration::from_secs(60)
    );
    assert_eq!(
        orphan_reconciliation_discovery_timeout(Duration::from_secs(15)),
        Duration::from_secs(15)
    );
}

#[test]
fn orphan_reconciliation_parses_lease_fences_and_plans_uid_preconditioned_deletion() {
    let dir = std::env::temp_dir().join(format!("sandboxwich-reconcile-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create reconciliation fake dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let orphan = SandboxId::new();
    let resident_lease = Uuid::new_v4();
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{log}"
case " $* " in
  *" get pod "*)
    printf '%s\n' 'Pod {orphan} sandboxwich-ci sandboxwich-{orphan} uid-orphan {resident_lease} 2020-01-01T00:00:00Z <none>'
    ;;
  *" delete "*)
    cat >> "{log}"
    ;;
esac
"#,
        log = log_path.display(),
    );
    std::fs::write(&script_path, script).expect("write reconciliation fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat reconciliation fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    let inventory = RuntimeResourceInventoryResponse {
        ok: true,
        provider: "kubernetes".to_string(),
        cluster: Some("k3s-ci".to_string()),
        namespace: "sandboxwich-ci".to_string(),
        sandbox_ids: Vec::new(),
        complete: true,
        resources: Vec::new(),
        active_resident_lease_ids: vec![resident_lease],
        next_cursor: None,
    };
    let limits = ReconciliationLimits {
        max_scanned: 10,
        max_deleted: 1,
        max_elapsed: Duration::from_secs(5),
    };
    let observed = ObservedKubernetesResource {
        sandbox_id: Some(orphan),
        resource_kind: RuntimeResourceKind::Pod,
        namespace: "sandboxwich-ci".to_string(),
        name: format!("sandboxwich-{orphan}"),
        uid: "uid-orphan".to_string(),
        resident_lease_id: Some(resident_lease),
        created_at: Some(Utc::now() - chrono::Duration::minutes(6)),
        volume_claim_phase: None,
    };
    assert_eq!(
        kubernetes_delete_path(&observed).expect("delete path"),
        format!("/api/v1/namespaces/sandboxwich-ci/pods/sandboxwich-{orphan}")
    );
    assert_eq!(
        kubernetes_delete_options(&observed)["preconditions"]["uid"],
        "uid-orphan"
    );

    let active = provider
        .reconcile_orphans(
            Ok(inventory.clone()),
            limits,
            true,
            &CancelSignal::never_cancelled(),
        )
        .expect("active resident reconciliation");
    assert_eq!(active.deleted, 0);
    assert_eq!(
        active.decisions[0].classification,
        ReconciliationClassification::Expected
    );

    let mut stale_inventory = inventory;
    stale_inventory.active_resident_lease_ids.clear();
    let stale = provider
        .reconcile_orphans(
            Ok(stale_inventory),
            limits,
            false,
            &CancelSignal::never_cancelled(),
        )
        .expect("stale resident reconciliation");
    assert_eq!(stale.deleted, 0);
    assert!(!stale.apply);
    assert_eq!(
        stale.decisions[0].classification,
        ReconciliationClassification::Orphaned
    );

    let unavailable = provider
        .reconcile_orphans(
            Err(anyhow::anyhow!("inventory unavailable")),
            limits,
            true,
            &CancelSignal::never_cancelled(),
        )
        .expect("inventory failure is fail-closed");
    assert_eq!(unavailable.deleted, 0);
    assert!(
        unavailable
            .decisions
            .iter()
            .all(|decision| !decision.delete_allowed)
    );
    let log = std::fs::read_to_string(&log_path).expect("read reconciliation kubectl log");
    assert!(
        log.contains("get pod --selector sandboxwich.dev/sandbox-id --output custom-columns="),
        "reconciliation must request a compact projection per resource kind: {log}"
    );
    assert!(
        log.contains("get networkpolicy --selector sandboxwich.dev/sandbox-id"),
        "reconciliation must split the formerly oversized multi-kind inventory: {log}"
    );
    assert!(
        !log.contains("get pod,persistentvolumeclaim,service,secret,networkpolicy"),
        "reconciliation must not rebuild the oversized combined JSON inventory: {log}"
    );
}

#[test]
fn orphan_reconciliation_deletes_inventory_resources_past_their_sandbox_ttl() {
    let dir = std::env::temp_dir().join(format!("sandboxwich-expired-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create expired reconciliation fake dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let sandbox_id = SandboxId::new();
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{log}"
case " $* " in
  *" get secret "*)
    printf '%s\n' 'Secret {sandbox_id} sandboxwich-ci sandboxwich-guest-token-{sandbox_id} uid-expired <none> 2020-01-01T00:00:00Z <none>'
    ;;
  *" delete "*)
    cat >> "{log}"
    ;;
esac
"#,
        log = log_path.display(),
    );
    std::fs::write(&script_path, script).expect("write expired reconciliation fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat expired reconciliation fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    let inventory = RuntimeResourceInventoryResponse {
        ok: true,
        provider: "kubernetes".to_string(),
        cluster: Some("k3s-ci".to_string()),
        namespace: "sandboxwich-ci".to_string(),
        sandbox_ids: vec![sandbox_id],
        complete: true,
        resources: vec![RuntimeResourceInventoryItem {
            sandbox_id,
            resource_kind: RuntimeResourceKind::Secret,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-guest-token-{sandbox_id}"),
            uid: "uid-expired".to_string(),
            expires_at: Some(Utc::now() - chrono::Duration::minutes(1)),
            cleanup_deadline: None,
        }],
        active_resident_lease_ids: Vec::new(),
        next_cursor: None,
    };

    let mut deleted_resources = Vec::new();
    let outcome = provider
        .reconcile_orphans_with_delete(
            Ok(inventory),
            ReconciliationLimits {
                max_scanned: 20,
                max_deleted: 1,
                max_elapsed: Duration::from_secs(5),
            },
            true,
            &CancelSignal::never_cancelled(),
            |resource, _, _| {
                deleted_resources.push(resource.clone());
                Ok(())
            },
        )
        .expect("expired reconciliation");

    assert_eq!(outcome.deleted, 1);
    assert!(outcome.decisions.iter().any(|decision| {
        decision.classification == ReconciliationClassification::Expired
            && decision
                .resource
                .as_ref()
                .is_some_and(|resource| resource.resource_kind == RuntimeResourceKind::Secret)
    }));
    assert_eq!(deleted_resources.len(), 1);
    assert_eq!(
        deleted_resources[0].resource_kind,
        RuntimeResourceKind::Secret
    );
    assert_eq!(
        outcome.classification_counts(),
        ReconciliationClassificationCounts {
            expired: 1,
            ..ReconciliationClassificationCounts::default()
        }
    );
}

/// Stateful fake kubectl that rejects the `kubectl apply` of one lowercase kind
/// with `stderr`, mirroring how the API server rejects a Pod whose namespace
/// ResourceQuota is exhausted.
fn write_stateful_fake_kubectl_rejecting_apply(
    rejected_kind: &str,
    stderr: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("sandboxwich-quota-kubectl-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create quota fake kubectl dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{log}"
case " $* " in
  *" get "*)
    kind=''
    name=''
    previous=''
    for arg in "$@"; do
      if [ "$previous" = get ]; then kind="$arg"; previous=kind; continue; fi
      if [ "$previous" = kind ]; then name="$arg"; break; fi
      previous="$arg"
    done
    kind=$(printf '%s' "$kind" | tr '[:upper:]' '[:lower:]')
    marker="{dir}/$kind-$name"
    [ -f "$marker" ] || exit 0
    python3 - "$marker" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
metadata = value.setdefault("metadata", {{}})
metadata["uid"] = "uid-" + metadata["name"]
metadata["generation"] = 1
print(json.dumps(value))
PY
    ;;
  *" apply "*)
    payload=$(cat)
    kind=$(printf '%s' "$payload" | sed -n 's/.*"kind": "\([^"]*\)".*/\1/p' | head -1 | tr '[:upper:]' '[:lower:]')
    name=$(printf '%s' "$payload" | sed -n 's/.*"name": "\([^"]*\)".*/\1/p' | head -1)
    if [ "$kind" = "{rejected_kind}" ]; then
      printf '%s\n' '{stderr}' >&2
      exit 1
    fi
    printf '%s' "$payload" > "{dir}/$kind-$name"
    ;;
  *" wait "*) ;;
  *" delete "*) ;;
esac
"#,
        log = log_path.display(),
        dir = dir.display(),
    );
    std::fs::write(&script_path, script).expect("write quota fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat quota fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod quota fake kubectl");
    }
    (script_path, log_path)
}

const QUOTA_REJECTION_STDERR: &str = r#"Error from server (Forbidden): error when creating "STDIN": pods "sandboxwich-quota" is forbidden: exceeded quota: sandbox-capacity, used: pods=40, limited: pods=40"#;

#[test]
fn staged_provision_rolls_back_its_workspace_claim_when_the_pod_is_quota_rejected() {
    // The 2026-08-03 leak in its original shape: the staged path applies the
    // workspace PVC first and the namespace ResourceQuota then rejects the Pod.
    let (kubectl, log_path) =
        write_stateful_fake_kubectl_rejecting_apply("pod", QUOTA_REJECTION_STDERR);
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();

    let error = provider
        .provision_staged(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
            |_| Ok(()),
        )
        .expect_err("a quota-rejected pod apply must fail the staged provision");
    assert!(
        error.to_string().contains("exceeded quota"),
        "the original quota rejection must not be masked by the rollback: {error:#}"
    );

    let log = std::fs::read_to_string(&log_path).expect("read quota kubectl log");
    assert!(
        log.contains(&format!(
            "delete pod,persistentvolumeclaim,service,networkpolicy,secret -l sandboxwich.dev/sandbox-id={sandbox_id}"
        )),
        "the staged claim must be deleted in the same failure path: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn staged_provision_does_not_roll_back_after_its_lease_is_lost() {
    // For a ProvisionSandbox lease the only reachable cancellation is
    // LeaseCancellationReason::LeaseLost, and main.rs cancels precisely so the
    // job stops instead of continuing against a lease it can no longer prove is
    // its own -- the job may already have been re-queued and completed by
    // another worker. rollback_applied_resources is a label-scoped delete with
    // no UID precondition that deliberately ignores the cancel signal, so
    // rolling back here would delete the new owner's live Pod, Services and
    // Bound workspace claim.
    let (kubectl, log_path) =
        write_stateful_fake_kubectl_rejecting_apply("pod", QUOTA_REJECTION_STDERR);
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();
    let cancelled = CancelSignal::new();
    let lease_lost = cancelled.clone();

    provider
        .provision_staged(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &cancelled,
            |report| {
                // The workspace claim is applied by the time this fires, so the
                // rollback guard -- not an empty apply set -- is what is under
                // test here.
                if report.stage == sandboxwich_core::ProvisioningStage::WorkspaceReady {
                    lease_lost.cancel();
                }
                Ok(())
            },
        )
        .expect_err("a cancelled staged provision must fail");

    let log = std::fs::read_to_string(&log_path).expect("read cancelled kubectl log");
    assert!(
        log.contains(" apply "),
        "the workspace claim must have been applied before the lease was lost: {log}"
    );
    assert!(
        !log.contains(" delete "),
        "a worker that lost its lease must not delete the new owner's resources: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

/// Builds an observed claim for the unbound-workspace-claim backstop cases.
fn observed_claim(
    sandbox_id: Option<SandboxId>,
    name: String,
    uid: &str,
    phase: Option<VolumeClaimPhase>,
    created_at: chrono::DateTime<Utc>,
) -> ObservedKubernetesResource {
    ObservedKubernetesResource {
        sandbox_id,
        resource_kind: RuntimeResourceKind::PersistentVolumeClaim,
        namespace: "sandboxwich-ci".to_string(),
        name,
        uid: uid.to_string(),
        resident_lease_id: None,
        created_at: Some(created_at),
        volume_claim_phase: phase,
    }
}

#[test]
fn stale_unbound_workspace_claims_are_reaped_and_every_other_claim_is_left_alone() {
    // 2026-08-03: 2,772 Pending sandboxwich-pvc-* claims accumulated in the
    // evalops-sandboxes namespace in three hours. Their sandbox rows still
    // existed, so `sandbox_ids` classified every one of them Indeterminate and
    // nothing ever deleted them.
    let now = Utc::now();
    let leaked = SandboxId::new();
    let bound_sandbox = SandboxId::new();
    let provisioning = SandboxId::new();
    let recorded = SandboxId::new();
    let unknown_phase = SandboxId::new();
    let inventory = ReconciliationInventory {
        sandbox_ids: std::collections::HashSet::from([
            leaked,
            bound_sandbox,
            provisioning,
            recorded,
            unknown_phase,
        ]),
        active_resident_lease_ids: std::collections::HashSet::new(),
        resources: vec![ExpectedKubernetesResource {
            sandbox_id: recorded,
            resource_kind: RuntimeResourceKind::PersistentVolumeClaim,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-pvc-{recorded}"),
            uid: "uid-recorded".to_string(),
            expires_at: None,
        }],
    };
    let observed = vec![
        observed_claim(
            Some(leaked),
            format!("sandboxwich-pvc-{leaked}"),
            "uid-leaked",
            Some(VolumeClaimPhase::Pending),
            now - chrono::Duration::hours(2),
        ),
        observed_claim(
            Some(bound_sandbox),
            format!("sandboxwich-pvc-{bound_sandbox}"),
            "uid-bound",
            Some(VolumeClaimPhase::Bound),
            now - chrono::Duration::hours(2),
        ),
        observed_claim(
            Some(provisioning),
            format!("sandboxwich-pvc-{provisioning}"),
            "uid-provisioning",
            Some(VolumeClaimPhase::Pending),
            now - chrono::Duration::minutes(2),
        ),
        observed_claim(
            Some(recorded),
            format!("sandboxwich-pvc-{recorded}"),
            "uid-recorded",
            Some(VolumeClaimPhase::Pending),
            now - chrono::Duration::hours(2),
        ),
        observed_claim(
            Some(unknown_phase),
            format!("sandboxwich-pvc-{unknown_phase}"),
            "uid-unknown-phase",
            None,
            now - chrono::Duration::hours(2),
        ),
        observed_claim(
            None,
            format!("sandboxwich-home-{}", HomeId::new()),
            "uid-home",
            Some(VolumeClaimPhase::Pending),
            now - chrono::Duration::hours(2),
        ),
    ];

    let decisions = classify_reconciliation(
        &inventory,
        &observed,
        &std::collections::HashMap::new(),
        now,
    );

    assert_eq!(
        decisions[0].classification,
        ReconciliationClassification::Orphaned,
        "a never-bound workspace claim older than the TTL with no control-plane record is residue"
    );
    assert!(decisions[0].delete_allowed);
    assert_eq!(
        decisions[1].classification,
        ReconciliationClassification::Indeterminate,
        "a Bound claim holds workspace data and is never reaped by the backstop"
    );
    assert!(!decisions[1].delete_allowed);
    assert_eq!(
        decisions[2].classification,
        ReconciliationClassification::Indeterminate,
        "a claim staged minutes ago belongs to a provision still in flight"
    );
    assert!(!decisions[2].delete_allowed);
    assert_eq!(
        decisions[3].classification,
        ReconciliationClassification::Expected,
        "a claim the control plane recorded stays on the archived-cleanup path"
    );
    assert!(!decisions[3].delete_allowed);
    assert_eq!(
        decisions[4].classification,
        ReconciliationClassification::Indeterminate,
        "an unreported phase must fail closed rather than be assumed Pending"
    );
    assert!(!decisions[4].delete_allowed);
    assert_eq!(
        decisions[5].classification,
        ReconciliationClassification::Indeterminate,
        "managed home claims outlive their runtimes and are out of scope"
    );
    assert!(!decisions[5].delete_allowed);
}

#[test]
fn reconciliation_discovery_reads_claim_phase_from_kubectl() {
    let dir = std::env::temp_dir().join(format!("sandboxwich-claim-phase-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create claim phase fake dir");
    let log_path = dir.join("log.txt");
    let script_path = dir.join("kubectl");
    let leaked = SandboxId::new();
    let bound = SandboxId::new();
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{log}"
case " $* " in
  *" get persistentvolumeclaim "*)
    printf '%s\n' 'PersistentVolumeClaim {leaked} sandboxwich-ci sandboxwich-pvc-{leaked} uid-leaked <none> 2020-01-01T00:00:00Z Pending'
    printf '%s\n' 'PersistentVolumeClaim {bound} sandboxwich-ci sandboxwich-pvc-{bound} uid-bound <none> 2020-01-01T00:00:00Z Bound'
    ;;
esac
"#,
        log = log_path.display(),
    );
    std::fs::write(&script_path, script).expect("write claim phase fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat claim phase fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    // Both sandbox rows are still live, which is exactly the state the leaked
    // claims were discovered in; neither claim was ever recorded as a runtime
    // resource.
    let inventory = RuntimeResourceInventoryResponse {
        ok: true,
        provider: "kubernetes".to_string(),
        cluster: Some("k3s-ci".to_string()),
        namespace: "sandboxwich-ci".to_string(),
        sandbox_ids: vec![leaked, bound],
        complete: true,
        resources: Vec::new(),
        active_resident_lease_ids: Vec::new(),
        next_cursor: None,
    };
    let outcome = provider
        .reconcile_orphans(
            Ok(inventory),
            ReconciliationLimits {
                max_scanned: 10,
                max_deleted: 1,
                max_elapsed: Duration::from_secs(5),
            },
            false,
            &CancelSignal::never_cancelled(),
        )
        .expect("claim phase reconciliation");
    assert_eq!(
        outcome.decisions[0].classification,
        ReconciliationClassification::Orphaned,
        "the Pending claim is provisioning residue"
    );
    assert!(outcome.decisions[0].delete_allowed);
    assert_eq!(
        outcome.decisions[1].classification,
        ReconciliationClassification::Indeterminate,
        "the Bound claim must never be deleted by reconciliation"
    );
    assert!(!outcome.decisions[1].delete_allowed);
    assert_eq!(
        kubernetes_delete_path(
            outcome.decisions[0]
                .resource
                .as_ref()
                .expect("orphan decision carries its resource")
        )
        .expect("delete path"),
        format!(
            "/api/v1/namespaces/sandboxwich-ci/persistentvolumeclaims/sandboxwich-pvc-{leaked}"
        )
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn slow_reconciliation_discovery_does_not_consume_the_delete_budget() {
    let dir = std::env::temp_dir().join(format!(
        "sandboxwich-reconciliation-budget-{}",
        SandboxId::new()
    ));
    std::fs::create_dir_all(&dir).expect("create reconciliation budget fake dir");
    let script_path = dir.join("kubectl");
    let orphan = SandboxId::new();
    let script = format!(
        r#"#!/bin/sh
set -eu
case " $* " in
  *" get persistentvolumeclaim "*)
    sleep 1
    printf '%s\n' 'PersistentVolumeClaim {orphan} sandboxwich-ci sandboxwich-pvc-{orphan} uid-orphan <none> 2020-01-01T00:00:00Z Pending'
    ;;
esac
"#,
    );
    std::fs::write(&script_path, script).expect("write reconciliation budget fake kubectl");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&script_path)
            .expect("stat reconciliation budget fake kubectl")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions).expect("chmod fake kubectl");
    }
    let provider = apply_provider_with_fake_kubectl(&script_path);
    let inventory = RuntimeResourceInventoryResponse {
        ok: true,
        provider: "kubernetes".to_string(),
        cluster: Some("k3s-ci".to_string()),
        namespace: "sandboxwich-ci".to_string(),
        sandbox_ids: vec![orphan],
        complete: true,
        resources: Vec::new(),
        active_resident_lease_ids: Vec::new(),
        next_cursor: None,
    };
    let mut delete_budget = None;
    let outcome = provider
        .reconcile_orphans_with_delete(
            Ok(inventory),
            ReconciliationLimits {
                max_scanned: 10,
                max_deleted: 1,
                max_elapsed: Duration::from_millis(1500),
            },
            true,
            &CancelSignal::never_cancelled(),
            |_, timeout, _| {
                delete_budget = Some(timeout);
                Ok(())
            },
        )
        .expect("slow discovery reconciliation");

    assert_eq!(outcome.deleted, 1);
    assert!(
        delete_budget.expect("eligible resource reached deletion") >= Duration::from_millis(1200),
        "deletion must receive its own bounded budget after discovery"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn provision_rolls_back_applied_resources_when_pod_never_becomes_ready() {
    let (kubectl, log_path) = write_fake_kubectl(Some("wait"));
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();

    let error = provider
        .provision(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("a pod that never becomes ready should fail provision");
    assert!(error.to_string().contains("did not become ready"));

    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        log.contains(" apply "),
        "expected an apply invocation, got: {log}"
    );
    assert!(
        log.contains(" wait "),
        "expected a wait invocation, got: {log}"
    );
    assert!(
        log.contains(" delete "),
        "expected a rollback delete invocation after the failed wait, got: {log}"
    );
    assert!(
        log.contains(&format!("sandboxwich.dev/sandbox-id={sandbox_id}")),
        "rollback delete should be scoped to the sandbox that failed to provision, got: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

#[test]
fn provision_rolls_back_applied_resources_when_apply_itself_fails() {
    // kubectl apply -f - with multiple documents is not atomic: some objects
    // can already exist by the time the command as a whole reports failure.
    let (kubectl, log_path) = write_fake_kubectl(Some("apply"));
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();

    let error = provider
        .provision(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("a failing kubectl apply should fail provision");
    assert!(error.to_string().contains("kubectl apply"));

    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        log.contains(" delete "),
        "expected a rollback delete invocation after the failed apply, got: {log}"
    );
    assert!(log.contains(&format!("sandboxwich.dev/sandbox-id={sandbox_id}")));

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

#[test]
fn fork_rolls_back_applied_resources_when_child_pod_never_becomes_ready() {
    let (kubectl, log_path) = write_fake_kubectl(Some("wait"));
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let parent_sandbox_id = SandboxId::new();
    let child_sandbox_id = SandboxId::new();
    let snapshot_id = SnapshotId::new();

    let error = provider
        .fork(
            parent_sandbox_id,
            child_sandbox_id,
            snapshot_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("a forked pod that never becomes ready should fail fork");
    assert!(error.to_string().contains("did not become ready"));

    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        log.contains(" delete "),
        "expected a rollback delete invocation for the fork, got: {log}"
    );
    assert!(
        log.contains(&format!("sandboxwich.dev/sandbox-id={child_sandbox_id}")),
        "rollback should be scoped to the child sandbox id (the one that was actually \
             applied for the fork), got: {log}"
    );
    assert!(
        !log.contains(&format!("sandboxwich.dev/sandbox-id={parent_sandbox_id}")),
        "rollback must not touch the parent sandbox's resources, got: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

#[test]
fn successful_provision_does_not_trigger_any_rollback_delete() {
    let (kubectl, log_path) = write_fake_kubectl(None);
    let provider = apply_provider_with_fake_kubectl(&kubectl);
    let sandbox_id = SandboxId::new();

    provider
        .provision(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("apply and wait both succeeding should provision successfully");

    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(log.contains(" apply "));
    assert!(log.contains(" wait "));
    assert!(
        !log.contains(" delete "),
        "a successful provision must not roll anything back, got: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

/// Like `write_fake_kubectl`, but instead of failing on `sleep_verb`, the
/// script drains stdin and then sleeps for `sleep_secs` before exiting
/// zero. Used to exercise the timeout/cancellation bound on a real
/// `SandboxProvider` mutating call (`provision`/`fork`/`stop`/
/// `create_snapshot`) rather than just `run_kubectl_command_async` in
/// isolation.
fn write_fake_kubectl_sleeping_on(
    sleep_verb: &'static str,
    sleep_secs: u64,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("sandboxwich-fake-kubectl-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create fake kubectl temp dir");
    let log_path = dir.join("log.txt");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             cat >/dev/null 2>&1 || true\n\
             case \" $* \" in\n\
             \x20\x20*\" {sleep_verb} \"*) sleep {sleep_secs} ;;\n\
             esac\n\
             exit 0\n",
        log = log_path.display(),
    );
    let script_path = dir.join("kubectl");
    std::fs::write(&script_path, script).expect("write fake kubectl script");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl script");
    }
    (script_path, log_path)
}

#[test]
fn provision_apply_is_bounded_by_the_kubectl_command_timeout_and_reports_a_retryable_error() {
    // Regression test for the "run_kubectl_documents is unbounded and blocking"
    // finding: `provision`'s `kubectl apply` used to run through
    // `std::process::Command::wait_with_output()` with no bound at all, so a
    // wedged API server hung the worker's job-execution thread forever, and its
    // failure (once it did occur) was an untyped `anyhow::Error` that
    // `classify_retry` treats as permanent. It must instead be bounded by the
    // provider's configured timeout and reported as a retryable
    // `ProviderError`.
    let (kubectl, _log_path) = write_fake_kubectl_sleeping_on("apply", 30);
    let provider = apply_provider_with_fake_kubectl(&kubectl)
        .with_kubectl_command_timeout(Duration::from_millis(200));
    let sandbox_id = SandboxId::new();

    let started = std::time::Instant::now();
    let error = provider
        .provision(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect_err("a wedged kubectl apply must not hang provision forever");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "provision should have been killed by the ~200ms timeout instead of \
             waiting anywhere near the fake kubectl's 30s sleep; elapsed = {elapsed:?}"
    );
    assert!(
        error.to_string().contains("timed out"),
        "expected a timeout error, got: {error}"
    );
    let disposition = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ProviderError>())
        .map(ProviderError::disposition);
    assert_eq!(
        disposition,
        Some(RetryDisposition::Retryable),
        "a wedged kubectl apply is transient infrastructure trouble and must be \
             classified retryable, not permanent; got {error:#}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

#[test]
fn provision_apply_is_cancelled_when_lease_renewal_is_lost() {
    // Regression test for "cancellation only threads through exec_handoff":
    // before this fix, `provision`'s `kubectl apply` (and its `kubectl wait`)
    // ran with no `CancelSignal` at all, so a worker that lost its lease mid-
    // provision kept mutating the cluster indefinitely instead of aborting.
    let (kubectl, _log_path) = write_fake_kubectl_sleeping_on("apply", 30);
    let provider = apply_provider_with_fake_kubectl(&kubectl)
        .with_kubectl_command_timeout(Duration::from_secs(60));
    let sandbox_id = SandboxId::new();

    let cancelled = CancelSignal::new();
    let flip_cancelled = cancelled.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        flip_cancelled.cancel();
    });

    let started = std::time::Instant::now();
    let error = provider
        .provision(sandbox_id, &SandboxProvisionSpec::default(), &cancelled)
        .expect_err("a cancelled apply must abort provision instead of completing");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "provision should have been cancelled almost immediately instead of \
             waiting anywhere near the fake kubectl's 30s sleep or 60s timeout; \
             elapsed = {elapsed:?}"
    );
    assert!(
        error.to_string().contains("cancelled"),
        "expected a cancellation error, got: {error}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

#[test]
fn provision_wait_for_pod_ready_is_cancelled_when_lease_renewal_is_lost() {
    // Same regression as above, but targeting `wait_for_pod_ready`
    // specifically: it used to be called with `cancelled: None` even though
    // it can block for up to 120s, which was the audit's headline example of
    // the worker mutating (well, waiting on a mutation of) the cluster past
    // the point where it could still prove it owned the lease.
    let (kubectl, log_path) = write_fake_kubectl_sleeping_on("wait", 30);
    let provider = apply_provider_with_fake_kubectl(&kubectl)
        .with_kubectl_command_timeout(Duration::from_secs(60));
    let sandbox_id = SandboxId::new();

    let cancelled = CancelSignal::new();
    let flip_cancelled = cancelled.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        flip_cancelled.cancel();
    });

    let started = std::time::Instant::now();
    let error = provider
        .provision(sandbox_id, &SandboxProvisionSpec::default(), &cancelled)
        .expect_err("a cancelled wait-for-ready must abort provision instead of completing");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "provision should have been cancelled almost immediately instead of \
             waiting anywhere near the fake kubectl's 30s sleep or 60s timeout; \
             elapsed = {elapsed:?}"
    );
    assert!(
        error.to_string().contains("cancelled"),
        "expected a cancellation error, got: {error}"
    );
    let log = std::fs::read_to_string(&log_path).expect("read fake kubectl log");
    assert!(
        log.contains(" apply "),
        "apply should have completed before the wait step began, got: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

#[test]
fn pod_ready_wait_uses_the_configured_kubectl_timeout() {
    let provider = apply_provider_with_fake_kubectl(std::path::Path::new("kubectl"))
        .with_kubectl_command_timeout(Duration::from_secs(600));
    assert_eq!(provider.pod_ready_timeout_arg(), "--timeout=595s");
}

#[test]
fn stop_is_cancelled_when_lease_renewal_is_lost() {
    let (kubectl, _log_path) = write_fake_kubectl_sleeping_on("delete", 30);
    let provider = apply_provider_with_fake_kubectl(&kubectl)
        .with_kubectl_command_timeout(Duration::from_secs(60));
    let sandbox_id = SandboxId::new();

    let cancelled = CancelSignal::new();
    let flip_cancelled = cancelled.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        flip_cancelled.cancel();
    });

    let started = std::time::Instant::now();
    let error = provider
        .stop(sandbox_id, &SandboxTeardownSpec::default(), &cancelled)
        .expect_err("a cancelled stop must abort instead of completing");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "stop should have been cancelled almost immediately instead of waiting \
             anywhere near the fake kubectl's 30s sleep or 60s timeout; elapsed = {elapsed:?}"
    );
    assert!(
        error.to_string().contains("cancelled"),
        "expected a cancellation error, got: {error}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

/// Like `write_fake_kubectl`, but the "wait" verb also writes `stdout_bytes`
/// bytes of `x` to stdout before exiting 0. Used to exercise the byte cap
/// end-to-end through `provision`'s real kubectl-invocation plumbing rather
/// than just unit-testing `cap_output_bytes` in isolation.
fn write_fake_kubectl_with_wait_stdout(
    stdout_bytes: usize,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("sandboxwich-fake-kubectl-{}", SandboxId::new()));
    std::fs::create_dir_all(&dir).expect("create fake kubectl temp dir");
    let log_path = dir.join("log.txt");
    let script = format!(
        "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> \"{log}\"\n\
             case \" $* \" in\n\
             \x20\x20*\" apply \"*) cat >/dev/null 2>&1 || true ;;\n\
             esac\n\
             case \" $* \" in\n\
             \x20\x20*\" wait \"*) head -c {stdout_bytes} /dev/zero | tr '\\0' 'x' ;;\n\
             esac\n\
             exit 0\n",
        log = log_path.display(),
    );
    let script_path = dir.join("kubectl");
    std::fs::write(&script_path, script).expect("write fake kubectl script");
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat fake kubectl script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod fake kubectl script");
    }
    (script_path, log_path)
}

#[test]
fn kubectl_output_is_capped_at_the_configured_byte_limit() {
    let (kubectl, _log_path) = write_fake_kubectl_with_wait_stdout(1024);
    let dry_run =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let provider = KubernetesApplyProvider::new(dry_run, kubectl.to_string_lossy().into_owned())
        .with_kubectl_context(Some("in-cluster".to_string()))
        .with_mutation_gate(true, true)
        .with_max_captured_output_bytes(16);
    let sandbox_id = SandboxId::new();

    let handle = provider
        .provision(
            sandbox_id,
            &SandboxProvisionSpec::default(),
            &CancelSignal::never_cancelled(),
        )
        .expect("provision against the fake kubectl should succeed");

    let wait_stdout = handle.metadata["waitStdout"]
        .as_str()
        .expect("waitStdout should be a string");
    // 1024 bytes of "x" produced by the fake kubectl must be capped well
    // below that, with a marker noting how much was cut.
    assert!(
        wait_stdout.len() < 1024,
        "expected captured waitStdout to be capped, got {} bytes",
        wait_stdout.len()
    );
    assert!(
        wait_stdout.contains("[truncated 1008 bytes]"),
        "expected a truncation marker for the omitted bytes, got: {wait_stdout:?}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("kubectl script has a parent dir"));
}

fn secret_mount_fixture(name: &str) -> SandboxSecretMount {
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
    SandboxSecretMount::from_ref(&SecretRef {
        id: SecretRefId::new(),
        tenant_id: "acme".into(),
        workspace_id: "ws-1".into(),
        name: name.into(),
        source: SecretSource {
            backend: SecretBackend::CsiSecretProviderClass,
            object_name: "acme-openai".into(),
            object_key: "api-key".into(),
        },
        delivery: SecretDelivery::File,
        state: SecretRefState::Active,
        created_at: now,
        updated_at: now,
        revoked_at: None,
    })
}

#[test]
fn kubernetes_pod_delivers_secret_references_as_read_only_csi_mounts() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_secret_csi_driver(Some("secrets-store.csi.k8s.io".to_string()));
    let spec = SandboxProvisionSpec {
        secret_mounts: vec![secret_mount_fixture("openai-api-key")],
        ..SandboxProvisionSpec::default()
    };
    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    let pod = &provisioned.metadata["manifests"]["pod"];

    let volume = pod["spec"]["volumes"]
        .as_array()
        .expect("volumes should be an array")
        .iter()
        .find(|volume| volume["name"] == "sandboxwich-secret-openai-api-key")
        .expect("secret delivery volume should be rendered");
    assert_eq!(volume["csi"]["driver"], "secrets-store.csi.k8s.io");
    assert_eq!(volume["csi"]["readOnly"], true);
    assert_eq!(
        volume["csi"]["volumeAttributes"]["secretProviderClass"],
        "acme-openai"
    );
    // No `secret`/`secretName` anywhere: the whole point of the CSI path is
    // that no Kubernetes Secret object ever holds this material.
    assert!(volume.get("secret").is_none());

    assert!(
        pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volume mounts should be an array")
            .iter()
            .any(|mount| mount["name"] == "sandboxwich-secret-openai-api-key"
                && mount["mountPath"] == "/run/sandboxwich/secrets/openai-api-key"
                && mount["readOnly"] == true)
    );
    // The guest learns the path, never the value.
    assert!(
        pod["spec"]["containers"][0]["env"]
            .as_array()
            .expect("env should be an array")
            .iter()
            .any(
                |env| env["name"] == "SANDBOXWICH_SECRET_OPENAI_API_KEY_FILE"
                    && env["value"] == "/run/sandboxwich/secrets/openai-api-key/api-key"
            )
    );
}

#[test]
fn kubernetes_provision_fails_closed_when_secret_csi_driver_is_unconfigured() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        secret_mounts: vec![secret_mount_fixture("openai-api-key")],
        ..SandboxProvisionSpec::default()
    };
    let error = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("a sandbox that asked for a credential must not come up without it");
    assert!(
        error.to_string().contains("Secrets Store CSI driver"),
        "unexpected error: {error}"
    );
}

#[test]
fn kubernetes_provision_rejects_duplicate_secret_mount_names() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_secret_csi_driver(Some("secrets-store.csi.k8s.io".to_string()));
    let spec = SandboxProvisionSpec {
        secret_mounts: vec![
            secret_mount_fixture("openai-api-key"),
            secret_mount_fixture("openai-api-key"),
        ],
        ..SandboxProvisionSpec::default()
    };
    let error = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("two mounts sharing a name render two Pod volumes with the same name");
    assert!(
        error.to_string().contains("appears more than once"),
        "unexpected error: {error}"
    );
}

#[test]
fn kubernetes_provision_rejects_secret_mounts_with_non_derived_paths() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_secret_csi_driver(Some("secrets-store.csi.k8s.io".to_string()));
    let mut mount = secret_mount_fixture("openai-api-key");
    mount.mount_dir = "/etc".into();
    mount.file_path = "/etc/api-key".into();
    let spec = SandboxProvisionSpec {
        secret_mounts: vec![mount],
        ..SandboxProvisionSpec::default()
    };
    let error = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("a delivery path the control plane did not derive must be refused");
    assert!(
        error.to_string().contains("not control-plane derived"),
        "unexpected error: {error}"
    );
}

#[test]
fn cloudflare_bridge_contract_is_bounded_and_fail_closed() {
    use crate::provider::cloudflare::{
        CloudflareConfig, CloudflareSandboxProvider, MAX_COMMAND_OUTPUT_BYTES,
        parse_sse_command_chunks, split_tenant_scope,
    };

    let config = CloudflareConfig {
        base_url: "https://bridge.example".into(),
        api_token: "bearer-secret".into(),
        request_timeout: Duration::from_secs(1),
        readiness_timeout: Duration::from_secs(1),
        replay_ledger_configured: false,
    };
    assert!(!format!("{config:?}").contains("bearer-secret"));
    assert_eq!(
        crate::provider::cloudflare::safe_bridge_code("upstream\nsecret"),
        "http_error"
    );
    assert_eq!(
        split_tenant_scope("org:workspace").unwrap(),
        ("org", "workspace")
    );
    assert!(split_tenant_scope("tenant:org:workspace").is_none());
    assert!(split_tenant_scope("org:").is_none());
    assert!(split_tenant_scope(":workspace").is_none());

    let encoded =
        base64::engine::general_purpose::STANDARD
            .encode(vec![b'x'; MAX_COMMAND_OUTPUT_BYTES + 100]);
    let output = format!(
        "event: stdout\ndata: {}\n\nevent: exit\ndata: {{\"exit_code\":0}}\n\n",
        encoded
    );
    let parsed = parse_sse_command_chunks(&[output.as_bytes()]).unwrap();
    assert!(parsed.stdout.len() <= MAX_COMMAND_OUTPUT_BYTES);
    assert_eq!(parsed.exit_code, Some(0));
    assert!(parse_sse_command_chunks(&[b"event: stdout\ndata: eA==\n\n"]).is_err());
    let chunks = output.as_bytes().chunks(7).collect::<Vec<_>>();
    let incremental = parse_sse_command_chunks(&chunks).unwrap();
    assert_eq!(incremental.exit_code, Some(0));

    let provider = CloudflareSandboxProvider::for_test();
    assert!(
        !provider
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::RunCommand)
    );
}

#[test]
fn cloudflare_bridge_normalizes_api_and_health_endpoints() {
    use crate::provider::cloudflare::{api_endpoint, health_endpoint};

    assert_eq!(
        api_endpoint("https://bridge.example", "/sandbox"),
        "https://bridge.example/v1/sandbox"
    );
    assert_eq!(
        api_endpoint("https://bridge.example/v1/", "/sandbox"),
        "https://bridge.example/v1/sandbox"
    );
    assert_eq!(
        health_endpoint("https://bridge.example/v1/"),
        "https://bridge.example/health"
    );
}

#[tokio::test]
async fn cloudflare_http_body_cap_is_enforced_incrementally() {
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let _ = socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await;
        let chunk = vec![b'x'; 256 * 1024];
        for _ in 0..9 {
            let size = format!("{:x}\r\n", chunk.len());
            if socket.write_all(size.as_bytes()).await.is_err() {
                return;
            }
            if socket.write_all(&chunk).await.is_err() {
                return;
            }
            if socket.write_all(b"\r\n").await.is_err() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut response = client
        .get(format!("http://{address}/oversized"))
        .send()
        .await
        .unwrap();
    let error = crate::provider::cloudflare::bounded_response_bytes(&mut response)
        .await
        .expect_err("an oversized connection-delimited response must fail while streaming");
    assert!(
        error.to_string().contains("bounded body limit"),
        "unexpected bounded response error: {error}"
    );
    server.abort();
    let _ = server.await;
}

#[test]
fn cloudflare_command_execution_is_blocked_without_replay_ledger() {
    use crate::provider::cloudflare::CloudflareSandboxProvider;
    let provider = CloudflareSandboxProvider::for_test();
    let spec = SandboxProvisionSpec {
        provider_preference: sandboxwich_core::ProviderPreference::Cloudflare,
        tenant_id: Some("org:workspace".into()),
        provider_external_id: Some("external".into()),
        provider_routing_scope: Some("org:workspace".into()),
        ..SandboxProvisionSpec::default()
    };
    let request = AgentCommandRequest {
        argv: vec!["true".into()],
        cwd: None,
        env: BTreeMap::new(),
        stdin: None,
        timeout_secs: None,
    };
    let error = provider
        .exec_handoff(
            SandboxId::new(),
            &spec,
            request,
            &CancelSignal::never_cancelled(),
        )
        .expect_err("headers alone must not claim replay-safe command execution");
    assert!(error.to_string().contains("durable replay ledger"));
}

#[test]
fn cloudflare_create_key_is_stable_for_lost_create_retries() {
    use crate::provider::cloudflare::create_idempotency_key;
    let sandbox_id = SandboxId::new();
    assert_eq!(
        create_idempotency_key(sandbox_id),
        create_idempotency_key(sandbox_id)
    );
}

#[test]
fn agent_sandbox_detached_launch_preserves_nonzero_exit_code() {
    let root = tempfile::tempdir().expect("tempdir");
    let state_dir = root.path().join("resident");
    let pid_file = state_dir.join("pid");
    let exit_file = state_dir.join("exit");
    let log_file = state_dir.join("log");
    let script = super::agent_sandbox_launch_script(
        state_dir.to_str().unwrap(),
        pid_file.to_str().unwrap(),
        exit_file.to_str().unwrap(),
        log_file.to_str().unwrap(),
    );
    std::process::Command::new("sh")
        .args([
            "-lc",
            &script,
            "sandboxwich-agent-resident",
            "sh",
            "-c",
            "exit 23",
        ])
        .status()
        .expect("launch detached process");
    for _ in 0..20 {
        if exit_file.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(std::fs::read_to_string(exit_file).unwrap(), "23");
}
