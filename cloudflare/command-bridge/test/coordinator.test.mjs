import assert from "node:assert/strict";
import test from "node:test";

import { CommandCoordinator } from "../src/coordinator.mjs";
import { DurableCommandLedger } from "../src/ledger.mjs";

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
  commandId: "019fd78e-f3f7-7da0-a1d4-69f47a05f010",
  intentDigestSha256: "b".repeat(64),
  organizationId: "org-1",
  workspaceId: "workspace-1",
  sandboxId: "sandbox-1",
  argv: ["/bin/sh", "-c", "printf once"],
  cwd: "/home/dex/threads/thread-1",
  env: { SAFE: "value" },
  stdin: null,
  timeoutSeconds: 30,
};

function completedProcess() {
  return {
    async waitForExit() {
      return { exitCode: 0 };
    },
    async getLogs() {
      return { stdout: "once", stderr: "" };
    },
    async getStatus() {
      return "completed";
    },
  };
}

test("concurrent duplicate delivery starts one Cloudflare process", async () => {
  const ledger = new DurableCommandLedger(new MemoryStorage());
  let starts = 0;
  let releaseStart;
  const startGate = new Promise((resolve) => {
    releaseStart = resolve;
  });
  const sandbox = {
    async mkdir(path, options) {
      assert.equal(path, intent.cwd);
      assert.deepEqual(options, { recursive: true });
    },
    async startProcess(command, options) {
      starts += 1;
      assert.equal(command, "'/bin/sh' '-c' 'printf once'");
      assert.equal(options.processId, intent.commandId);
      assert.equal(options.autoCleanup, false);
      await startGate;
      return completedProcess();
    },
    async getProcess() {
      return null;
    },
  };
  const coordinator = new CommandCoordinator(ledger, sandbox);

  const first = coordinator.execute(intent);
  while (starts === 0) await new Promise((resolve) => setImmediate(resolve));
  const duplicate = await coordinator.execute(structuredClone(intent));
  assert.equal(duplicate.status, "in_progress");
  releaseStart();
  assert.equal((await first).status, "completed");
  assert.equal(starts, 1);
});

test("lost dispatch response reconciles the deterministic process without restarting", async () => {
  const storage = new MemoryStorage();
  const ledger = new DurableCommandLedger(storage);
  let starts = 0;
  const process = completedProcess();
  const firstSandbox = {
    async startProcess(_command, options) {
      starts += 1;
      assert.equal(options.processId, intent.commandId);
      throw new Error("response_lost");
    },
    async getProcess(id) {
      assert.equal(id, intent.commandId);
      return process;
    },
  };

  const first = await new CommandCoordinator(ledger, firstSandbox).execute(intent);
  assert.equal(first.status, "completed");
  assert.equal(starts, 1);

  const restartedSandbox = {
    async startProcess() {
      starts += 1;
      throw new Error("must not restart");
    },
    async getProcess() {
      return process;
    },
  };
  const replay = await new CommandCoordinator(
    new DurableCommandLedger(storage),
    restartedSandbox,
  ).execute(structuredClone(intent));
  assert.equal(replay.status, "completed");
  assert.equal(replay.record.terminal.stdout, "once");
  assert.equal(starts, 1);
});

test("unobservable dispatch remains indeterminate and is never reclaimed", async () => {
  const storage = new MemoryStorage();
  let starts = 0;
  const unavailable = {
    async startProcess() {
      starts += 1;
      throw new Error("response_lost");
    },
    async getProcess() {
      return null;
    },
  };
  const first = await new CommandCoordinator(
    new DurableCommandLedger(storage),
    unavailable,
  ).execute(intent);
  assert.equal(first.status, "indeterminate");

  const duplicate = await new CommandCoordinator(
    new DurableCommandLedger(storage),
    unavailable,
  ).execute(structuredClone(intent));
  assert.equal(duplicate.status, "indeterminate");
  assert.equal(starts, 1);
});

test("restart result lookup replays durable output without touching Cloudflare", async () => {
  const storage = new MemoryStorage();
  const firstCoordinator = new CommandCoordinator(new DurableCommandLedger(storage), {
    async startProcess() {
      return completedProcess();
    },
    async getProcess() {
      return null;
    },
  });
  await firstCoordinator.execute(intent);

  const restarted = new CommandCoordinator(new DurableCommandLedger(storage), {
    async startProcess() {
      throw new Error("must not dispatch terminal command");
    },
    async getProcess() {
      throw new Error("must not query terminal command");
    },
  });
  const result = await restarted.lookup(intent.commandId, intent.intentDigestSha256, 0);
  assert.equal(result.status, "completed");
  assert.deepEqual(result.events.map((event) => event.name), ["stdout", "exit"]);
});
