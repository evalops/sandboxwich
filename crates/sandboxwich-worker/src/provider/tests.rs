use super::*;

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
fn configured_workspace_storage_overrides_non_default_tier_disk_size() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_workspace_storage(Some("20Gi".to_string()));
    let spec = SandboxProvisionSpec {
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
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
            .with_runtime_class_name(Some("gvisor".to_string()));
    let spec = SandboxProvisionSpec {
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.0.0.0/8".to_string(),
            }],
        },
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
            .contains(&WorkerCapability::GvisorSandbox)
    );
}

#[test]
fn kubernetes_dry_run_rejects_host_allow_rules_for_standard_network_policy() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }],
        },
    };

    let error = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect_err("host allow rules should not silently render deny-all");
    assert!(error.to_string().contains("cannot enforce host allow rule"));
}

#[test]
fn cilium_fqdn_backend_renders_host_allow_rules() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None)
            .with_cilium_fqdn_egress(true);
    let spec = SandboxProvisionSpec {
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Host,
                value: "api.example.com".to_string(),
            }],
        },
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
        timeout_secs: None,
    };

    let exec_args = apply.exec_args(SandboxId::new(), &request);

    assert!(!exec_args.contains(&"-i".to_string()));
    assert!(!exec_args.contains(&"bash".to_string()));
    assert!(KubernetesApplyProvider::exec_stdin_payload(&request).is_none());
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.0.0.0/8".to_string(),
            }],
        },
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "192.168.1.0/24".to_string(),
            }],
        },
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "169.254.169.0/24".to_string(),
            }],
        },
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "10.42.0.0/16".to_string(),
            }],
        },
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "0.0.0.0/0".to_string(),
            }],
        },
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "fd00::/8".to_string(),
            }],
        },
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::Allowlist {
            rules: vec![sandboxwich_core::NetworkAllowRule {
                kind: NetworkAllowRuleKind::Cidr,
                value: "2001:db8::/32".to_string(),
            }],
        },
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
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
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::AllowAll,
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
fn deny_all_egress_still_renders_no_egress_rules() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);
    let spec = SandboxProvisionSpec {
        memory_limit: MemoryLimit::OneG,
        network_egress: NetworkEgress::DenyAll,
    };

    let provisioned = provider
        .provision(SandboxId::new(), &spec, &CancelSignal::never_cancelled())
        .expect("dry-run provision should succeed");
    assert_eq!(
        provisioned.metadata["manifests"]["networkPolicy"]["spec"]["egress"],
        json!([])
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
        memory_limit: MemoryLimit::FourG,
        network_egress: NetworkEgress::DenyAll,
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
        .stop(SandboxId::new(), &CancelSignal::never_cancelled())
        .expect_err("stop without the mutation gate should fail closed");
    assert!(error.to_string().contains("--confirm-apply"));
}

#[test]
fn dry_run_stop_is_a_successful_no_op() {
    let provider =
        KubernetesDryRunProvider::with_snapshot_class("k3s-ci", "sandboxwich-ci", None, None);

    provider
        .stop(SandboxId::new(), &CancelSignal::never_cancelled())
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
        .stop(sandbox_id, &cancelled)
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
