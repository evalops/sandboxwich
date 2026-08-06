import assert from "node:assert/strict";
import test from "node:test";

import {
  DurableCommandLedger,
  DurableSandboxLedger,
  LedgerConflict,
} from "../src/ledger.mjs";

class MemoryStorage {
  values = new Map();
  transactionTail = Promise.resolve();

  async transaction(callback) {
    const previous = this.transactionTail;
    let release;
    this.transactionTail = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await callback(this);
    } finally {
      release();
    }
  }

  async get(key) {
    return structuredClone(this.values.get(key));
  }

  async put(key, value) {
    this.values.set(key, structuredClone(value));
  }

  async list({ prefix }) {
    return new Map(
      [...this.values.entries()]
        .filter(([key]) => key.startsWith(prefix))
        .map(([key, value]) => [key, structuredClone(value)]),
    );
  }
}

const intent = {
  commandId: "019fd78e-f3f7-7da0-a1d4-69f47a05f001",
  intentDigestSha256: "a".repeat(64),
  organizationId: "org-1",
  workspaceId: "workspace-1",
  sandboxId: "sandbox-1",
  argv: ["/bin/sh", "-c", "printf once"],
  cwd: "/home/dex/threads/thread-1",
  timeoutSeconds: 30,
};

test("duplicate before dispatch returns the accepted durable intent", async () => {
  const ledger = new DurableCommandLedger(new MemoryStorage());
  const first = await ledger.admit(intent);
  const duplicate = await ledger.admit(structuredClone(intent));

  assert.equal(first.accepted, true);
  assert.equal(first.record.state, "accepted");
  assert.equal(duplicate.accepted, false);
  assert.equal(duplicate.record.state, "accepted");
});

test("duplicate during execution cannot claim a second dispatch", async () => {
  const ledger = new DurableCommandLedger(new MemoryStorage());
  await ledger.admit(intent);
  assert.equal(await ledger.claimDispatch(intent.commandId, intent.intentDigestSha256), true);

  const duplicate = await ledger.admit(structuredClone(intent));
  assert.equal(duplicate.record.state, "dispatching");
  assert.equal(await ledger.claimDispatch(intent.commandId, intent.intentDigestSha256), false);
});

test("duplicate after completion replays the stored terminal result", async () => {
  const ledger = new DurableCommandLedger(new MemoryStorage());
  await ledger.admit(intent);
  await ledger.claimDispatch(intent.commandId, intent.intentDigestSha256);
  await ledger.append(intent.commandId, intent.intentDigestSha256, {
    name: "stdout",
    value: "b25jZQ==",
  });
  await ledger.complete(intent.commandId, intent.intentDigestSha256, {
    exitCode: 0,
    stdout: "once",
    stderr: "",
  });

  const duplicate = await ledger.admit(structuredClone(intent));
  const replay = await ledger.replay(intent.commandId, intent.intentDigestSha256, 0);
  assert.equal(duplicate.record.state, "completed");
  assert.equal(replay.record.terminal.stdout, "once");
  assert.deepEqual(replay.events.map((event) => event.name), ["stdout", "exit"]);
});

test("ambiguous dispatch remains indeterminate after worker restart", async () => {
  const storage = new MemoryStorage();
  const firstWorker = new DurableCommandLedger(storage);
  await firstWorker.admit(intent);
  await firstWorker.claimDispatch(intent.commandId, intent.intentDigestSha256);
  await firstWorker.markIndeterminate(
    intent.commandId,
    intent.intentDigestSha256,
    "dispatch_response_lost",
  );

  const restartedWorker = new DurableCommandLedger(storage);
  assert.equal(
    await restartedWorker.claimDispatch(intent.commandId, intent.intentDigestSha256),
    false,
  );
  const record = await restartedWorker.get(intent.commandId);
  assert.equal(record.state, "indeterminate");
  assert.equal(record.reconcileReason, "dispatch_response_lost");
});

test("worker restart preserves result lookup and cursor replay", async () => {
  const storage = new MemoryStorage();
  const firstWorker = new DurableCommandLedger(storage);
  await firstWorker.admit(intent);
  await firstWorker.claimDispatch(intent.commandId, intent.intentDigestSha256);
  await firstWorker.append(intent.commandId, intent.intentDigestSha256, {
    name: "stdout",
    value: "YQ==",
  });
  await firstWorker.append(intent.commandId, intent.intentDigestSha256, {
    name: "stderr",
    value: "Yg==",
  });
  await firstWorker.complete(intent.commandId, intent.intentDigestSha256, {
    exitCode: 0,
    stdout: "a",
    stderr: "b",
  });

  const restartedWorker = new DurableCommandLedger(storage);
  const replay = await restartedWorker.replay(
    intent.commandId,
    intent.intentDigestSha256,
    1,
  );
  assert.deepEqual(replay.events.map((event) => event.sequence), [2, 3]);
  assert.equal(replay.cursor, 3);
  assert.equal((await restartedWorker.get(intent.commandId)).terminal.exitCode, 0);
});

test("same command id with a different intent fails closed", async () => {
  const ledger = new DurableCommandLedger(new MemoryStorage());
  await ledger.admit(intent);
  await assert.rejects(
    ledger.admit({ ...intent, argv: ["touch", "twice"] }),
    (error) => error instanceof LedgerConflict && error.code === "command_intent_conflict",
  );
});

test("duplicate sandbox creation returns the same deterministic identity", async () => {
  const ledger = new DurableSandboxLedger(new MemoryStorage());
  const identity = {
    sandboxId: "sandbox-1",
    homeId: "home-1",
    organizationId: "org-1",
    workspaceId: "workspace-1",
  };

  assert.equal((await ledger.ensure(identity)).created, true);
  const duplicate = await ledger.ensure(structuredClone(identity));
  assert.equal(duplicate.created, false);
  assert.deepEqual(duplicate.identity, identity);
  await assert.rejects(
    ledger.ensure({ ...identity, homeId: "home-other" }),
    (error) => error instanceof LedgerConflict && error.code === "sandbox_identity_conflict",
  );
});
