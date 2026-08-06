import assert from "node:assert/strict";
import test from "node:test";

import {
  BridgeContractError,
  attachIntentDigest,
  capabilityReport,
  normalizeCommand,
} from "../src/contract.mjs";

const bindings = {
  COMMAND_LEDGER: {},
  Sandbox: {},
  DEX_COMPUTER_HOME: {},
  BRIDGE_TOKEN: "a-production-length-secret",
};

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
