import assert from "node:assert/strict";
import test from "node:test";

import {
  BridgeContractError,
  attachIntentDigest,
  capabilityReport,
  normalizeCommand,
  recoveryIdentityRequest,
} from "../src/contract.mjs";

const bindings = {
  COMMAND_LEDGER: {},
  Sandbox: {},
  DEX_COMPUTER_HOME: {},
  BRIDGE_TOKEN: "a-production-length-secret",
  RECOVERY_TENANT: "evalops-platform",
  RECOVERY_SANDBOX_IDS: "sandbox-1",
};

test("stored identity recovery is fenced by stable sandbox id and tenant hint", () => {
  const request = new Request("https://bridge/v1/sandbox/sandbox-1", {
    method: "DELETE",
    headers: {
      "x-sandboxwich-recover-identity": "stored",
      "x-sandboxwich-sandbox-id": "sandbox-1",
      "x-sandboxwich-recovery-tenant": "evalops-platform",
    },
  });

  assert.deepEqual(recoveryIdentityRequest(request, "sandbox-1", "evalops-platform", "sandbox-1"), {
    tenantHint: "evalops-platform",
  });
  assert.throws(
    () => recoveryIdentityRequest(request, "sandbox-1", "tenant-other", "sandbox-1"),
    (error) => error instanceof BridgeContractError && error.code === "recovery_tenant_mismatch",
  );
  assert.throws(
    () => recoveryIdentityRequest(request, "sandbox-other", "evalops-platform", "sandbox-1"),
    (error) => error instanceof BridgeContractError && error.code === "sandbox_identity_mismatch",
  );
  assert.throws(
    () => recoveryIdentityRequest(request, "sandbox-1", "evalops-platform", "sandbox-other"),
    (error) => error instanceof BridgeContractError && error.code === "recovery_target_not_allowed",
  );
});

test("command capability is absent when any durable binding is missing", () => {
  for (const missing of Object.keys(bindings)) {
    const env = { ...bindings };
    delete env[missing];
    const report = capabilityReport(env);
    assert.equal(report.ok, false, missing);
    assert.deepEqual(report.capabilities, [], missing);
  }
});

test("command capability is present with ledger, sandbox, home, and token bindings", () => {
  const report = capabilityReport(bindings);
  assert.equal(report.ok, true);
  assert.deepEqual(report.capabilities, [
    "sandbox.create",
    "sandbox.exec",
    "sandbox.result-replay",
  ]);
});

test("canonical command digest is stable across environment key order", async () => {
  const identity = {
    organizationId: "org-1",
    workspaceId: "workspace-1",
    sandboxId: "sandbox-1",
  };
  const left = normalizeCommand(
    { argv: ["sh", "-c", "printf once"], env: { B: "2", A: "1" } },
    identity,
    "command-1",
  );
  const right = normalizeCommand(
    { argv: ["sh", "-c", "printf once"], env: { A: "1", B: "2" } },
    identity,
    "command-1",
  );
  assert.equal(
    (await attachIntentDigest(left)).intentDigestSha256,
    (await attachIntentDigest(right)).intentDigestSha256,
  );
});

test("command cwd cannot escape the durable home", () => {
  assert.throws(
    () =>
      normalizeCommand(
        { argv: ["pwd"], cwd: "/tmp" },
        { organizationId: "org-1", workspaceId: "ws-1", sandboxId: "sandbox-1" },
        "command-1",
      ),
    (error) =>
      error instanceof BridgeContractError && error.code === "command_cwd_outside_home",
  );
});
