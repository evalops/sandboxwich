use std::{process::Stdio, thread, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use sandboxwich_core::AgentSandboxActivationV1;

#[test]
fn preclaim_pid1_waits_for_activation_then_reports_pod_bound_ready() {
    let root = tempfile::tempdir().expect("tempdir");
    let bundle = root.path().join("activation.json");
    let marker = root.path().join("activation.ready");
    let ready = root.path().join("ready");
    let activation = AgentSandboxActivationV1 {
        version: AgentSandboxActivationV1::VERSION,
        claim_uid: "claim-uid".into(),
        sandbox_uid: "sandbox-uid".into(),
        pod_uid: "pod-uid".into(),
        image_digest: "sha256:image".into(),
        bootstrap_digest: "sha256:bootstrap".into(),
        policy_digest: "sha256:policy".into(),
        expires_at: Utc::now() + ChronoDuration::minutes(1),
        nonce: "nonce".into(),
        signature: "verified-before-pid1".into(),
    };
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sandboxwich-agent"))
        .args([
            "agent-sandbox-preclaim",
            "--bundle",
            bundle.to_str().unwrap(),
            "--ready-file",
            ready.to_str().unwrap(),
            "--activation-marker",
            marker.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start preclaim PID1");
    thread::sleep(Duration::from_millis(150));
    assert!(
        !ready.exists(),
        "preclaim must not report ready before claim activation"
    );
    let mut invalid = activation.clone();
    invalid.nonce = "invalid".into();
    std::fs::write(&bundle, serde_json::to_vec(&invalid).unwrap()).unwrap();
    thread::sleep(Duration::from_millis(150));
    assert!(!ready.exists(), "unverified bundle must not launch");
    std::fs::write(&bundle, serde_json::to_vec(&activation).unwrap()).unwrap();
    std::fs::write(&marker, activation.nonce.as_bytes()).unwrap();
    for _ in 0..30 {
        if ready.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(std::fs::read_to_string(&ready).unwrap(), "pod-uid");
    child.kill().expect("stop launcher");
    let _ = child.wait();
}
