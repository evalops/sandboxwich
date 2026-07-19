use super::*;
use sandboxwich_core::{MAX_COMMAND_STDIN_BYTES, NetworkAllowRule};

fn isolated_sidecar_spec(bootstrap: &[u8]) -> IsolatedResidentProcessSpec {
    IsolatedResidentProcessSpec {
        sandbox_id: SandboxId::new(),
        process_id: sandboxwich_core::ResidentProcessId::new(),
        generation: 7,
        lease_id: Uuid::now_v7(),
        argv: vec!["/opt/orb/bin/orb-sidecar".to_string()],
        cwd: Some("/workspace".to_string()),
        env: BTreeMap::from([("ORB_API".to_string(), "https://orb.invalid".to_string())]),
        bootstrap: IsolatedResidentProcessBootstrap {
            content: bootstrap.to_vec(),
            target_file: "/run/sandboxwich/bootstrap/orb-token".to_string(),
            mode: 0o400,
            placement_attestation: None,
        },
    }
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
    spec.bootstrap.placement_attestation = Some(b"placement-attestation-canary".to_vec());

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
    spec.bootstrap.target_file = RESIDENT_PLACEMENT_ATTESTATION_FILE.to_string();
    spec.bootstrap.placement_attestation = Some(b"attestation".to_vec());
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
fn isolated_sidecar_pending_is_not_acknowledged_and_times_out_retryably() {
    let (kubectl, log_path) = write_pending_isolated_sidecar_fake_kubectl();
    let provider = isolated_sidecar_apply_provider(&kubectl)
        .with_isolated_resident_process_startup_timeout(Duration::from_millis(45));
    let mut observations = Vec::new();
    let error = provider
        .run_isolated_resident_process(
            &isolated_sidecar_spec(b"pending-deadline-canary"),
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
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].state, IsolatedResidentProcessState::Failed);
    assert_eq!(observations[0].pod_uid.as_deref(), Some("pending-pod-uid"));

    let dir = kubectl.parent().expect("pending fake kubectl parent");
    let get_count: usize = std::fs::read_to_string(dir.join("get.count"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        get_count <= 5,
        "bounded backoff should cap API calls during the 45ms deadline, got {get_count}"
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
            workspace_mode: mode.clone(),
            execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
            memory_limit: MemoryLimit::OneG,
            network_egress: NetworkEgress::DenyAll,
            runtime_profile: Default::default(),
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
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
        runtime_profile: Default::default(),
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

    let kata =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_isolation_profile(IsolationProfile::Kata)
            .with_runtime_class_name(Some("kata-qemu".to_string()));
    assert!(
        kata.capability_report()
            .capabilities
            .contains(&WorkerCapability::VirtualMachine)
    );
    assert!(
        !kata
            .capability_report()
            .capabilities
            .contains(&WorkerCapability::SandboxedContainer)
    );
}

#[test]
fn kubernetes_dry_run_rejects_host_allow_rules_for_standard_network_policy() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
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
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
        runtime_profile: Default::default(),
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
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
        runtime_profile: Default::default(),
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
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
        runtime_profile: Default::default(),
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
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::DenyAll,
        runtime_profile: Default::default(),
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
        workspace_mode: sandboxwich_core::WorkspaceMode::Persistent,
        execution_class: sandboxwich_core::ExecutionClass::DevelopmentContainer,
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
        runtime_profile: Default::default(),
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

    let args = apply.teardown_args_with_spec(
        SandboxId::new(),
        &SandboxTeardownSpec {
            delete_gke_fqdn_policy: true,
        },
    );

    assert!(args.contains(&format!(
        "{SANDBOX_TEARDOWN_RESOURCE_KINDS},{GKE_FQDN_RESOURCE_KIND}"
    )));
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

fn apply_provider_with_fake_kubectl(kubectl: &std::path::Path) -> KubernetesApplyProvider {
    let dry_run =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    KubernetesApplyProvider::new(dry_run, kubectl.to_string_lossy().into_owned())
        .with_kubectl_context(Some("in-cluster".to_string()))
        .with_mutation_gate(true, true)
}

fn write_stateful_fake_kubectl() -> (std::path::PathBuf, std::path::PathBuf) {
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
    printf '%s' "$payload" > "{dir}/$kind-$name"
    ;;
  *" wait "*) ;;
esac
"#,
        log = log_path.display(),
        dir = dir.display(),
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
    assert!(
        log.matches(" get ").count() >= 10,
        "expected pre/post reads: {log}"
    );
    assert_eq!(
        log.matches(" apply ").count(),
        5,
        "one apply per manifest: {log}"
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
        "workspace, secret, policy, pod, and two services: {log}"
    );

    let _ = std::fs::remove_dir_all(kubectl.parent().expect("fake kubectl parent"));
}

#[test]
fn provision_staged_applies_gateway_policy_and_waits_for_gateway_before_runtime() {
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
    let runtime_apply = log
        .rfind(&format!("sandboxwich-{sandbox_id}"))
        .expect("runtime apply");
    assert!(
        gateway_wait < runtime_apply,
        "gateway must be ready first: {log}"
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
    let error = provider
        .provision_staged(
            SandboxId::new(),
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
        },
        ObservedKubernetesResource {
            sandbox_id: Some(orphan_sandbox),
            resource_kind: RuntimeResourceKind::Service,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-{orphan_sandbox}"),
            uid: "uid-orphan".to_string(),
            resident_lease_id: None,
            created_at: None,
        },
        ObservedKubernetesResource {
            sandbox_id: Some(expired_sandbox),
            resource_kind: RuntimeResourceKind::PersistentVolumeClaim,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-pvc-{expired_sandbox}"),
            uid: "uid-expired".to_string(),
            resident_lease_id: None,
            created_at: None,
        },
        ObservedKubernetesResource {
            sandbox_id: None,
            resource_kind: RuntimeResourceKind::Pod,
            namespace: "sandboxwich-ci".to_string(),
            name: "foreign-pod".to_string(),
            uid: "uid-foreign".to_string(),
            resident_lease_id: None,
            created_at: None,
        },
        ObservedKubernetesResource {
            sandbox_id: Some(live_sandbox),
            resource_kind: RuntimeResourceKind::Pod,
            namespace: "sandboxwich-ci".to_string(),
            name: format!("sandboxwich-{live_sandbox}"),
            uid: "replacement-uid".to_string(),
            resident_lease_id: None,
            created_at: None,
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
  *" get "*)
    printf '%s\n' '{{"items":[{{"kind":"Pod","metadata":{{"namespace":"sandboxwich-ci","name":"sandboxwich-{orphan}","uid":"uid-orphan","creationTimestamp":"2020-01-01T00:00:00Z","labels":{{"sandboxwich.dev/sandbox-id":"{orphan}","sandboxwich.dev/lease-id":"{resident_lease}"}}}}}}]}}'
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
