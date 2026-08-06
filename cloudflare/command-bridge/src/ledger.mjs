export class LedgerConflict extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const COMMAND_ID = /^[A-Za-z0-9._:-]{1,256}$/;
const SHA256 = /^[0-9a-f]{64}$/;

export class DurableCommandLedger {
  constructor(storage) {
    this.storage = storage;
  }

  async admit(intent) {
    validateIntent(intent);
    return this.storage.transaction(async (transaction) => {
      const key = commandKey(intent.commandId);
      const existing = await transaction.get(key);
      if (existing) {
        assertSameIntent(existing.intent, intent);
        return { accepted: false, record: existing };
      }
      const record = {
        intent,
        state: "accepted",
        cursor: 0,
        terminal: null,
        createdAt: Date.now(),
      };
      await transaction.put(key, record);
      return { accepted: true, record };
    });
  }

  async claimDispatch(commandId, digest) {
    return this.storage.transaction(async (transaction) => {
      const key = commandKey(commandId);
      const record = await transaction.get(key);
      assertRecord(record, digest);
      if (record.state !== "accepted") return false;
      record.state = "dispatching";
      record.dispatchedAt = Date.now();
      await transaction.put(key, record);
      return true;
    });
  }

  async markRunning(commandId, digest) {
    return this.storage.transaction(async (transaction) => {
      const key = commandKey(commandId);
      const record = await transaction.get(key);
      assertRecord(record, digest);
      if (record.terminal) return record;
      if (record.state === "accepted") {
        throw new LedgerConflict("command_not_dispatched");
      }
      if (record.state !== "indeterminate") record.state = "running";
      record.runningAt ??= Date.now();
      await transaction.put(key, record);
      return record;
    });
  }

  async markIndeterminate(commandId, digest, reason) {
    return this.storage.transaction(async (transaction) => {
      const key = commandKey(commandId);
      const record = await transaction.get(key);
      assertRecord(record, digest);
      if (record.terminal) return record;
      if (record.state === "accepted") {
        throw new LedgerConflict("command_not_dispatched");
      }
      record.state = "indeterminate";
      record.reconcileReason = safeReason(reason);
      record.indeterminateAt ??= Date.now();
      await transaction.put(key, record);
      return record;
    });
  }

  async append(commandId, digest, event) {
    return this.storage.transaction(async (transaction) => {
      const key = commandKey(commandId);
      const record = await transaction.get(key);
      assertRecord(record, digest);
      if (record.terminal) throw new LedgerConflict("command_already_terminal");
      const sequence = record.cursor + 1;
      const durableEvent = { ...event, sequence };
      record.cursor = sequence;
      await transaction.put(eventKey(commandId, sequence), durableEvent);
      await transaction.put(key, record);
      return durableEvent;
    });
  }

  async complete(commandId, digest, terminal) {
    return this.storage.transaction(async (transaction) => {
      const key = commandKey(commandId);
      const record = await transaction.get(key);
      assertRecord(record, digest);
      if (record.terminal) {
        if (!sameTerminal(record.terminal, terminal)) {
          throw new LedgerConflict("command_terminal_conflict");
        }
        return record;
      }
      const sequence = record.cursor + 1;
      record.cursor = sequence;
      record.state = "completed";
      record.terminal = { ...terminal, sequence };
      await transaction.put(eventKey(commandId, sequence), {
        name: "exit",
        sequence,
        exitCode: terminal.exitCode,
      });
      await transaction.put(key, record);
      return record;
    });
  }

  async fail(commandId, digest, code) {
    return this.storage.transaction(async (transaction) => {
      const key = commandKey(commandId);
      const record = await transaction.get(key);
      assertRecord(record, digest);
      if (record.terminal) {
        if (record.state !== "failed" || record.terminal.code !== code) {
          throw new LedgerConflict("command_terminal_conflict");
        }
        return record;
      }
      const sequence = record.cursor + 1;
      record.cursor = sequence;
      record.state = "failed";
      record.terminal = { exitCode: 1, code: safeReason(code), sequence };
      await transaction.put(eventKey(commandId, sequence), {
        name: "error",
        sequence,
        code: record.terminal.code,
      });
      await transaction.put(key, record);
      return record;
    });
  }

  async replay(commandId, digest, after = 0) {
    return this.storage.transaction(async (transaction) => {
      const record = await transaction.get(commandKey(commandId));
      assertRecord(record, digest);
      if (!Number.isSafeInteger(after) || after < 0 || after > record.cursor) {
        throw new LedgerConflict("command_replay_cursor_invalid");
      }
      const entries = await transaction.list({ prefix: eventPrefix(commandId) });
      const events = [...entries.values()]
        .filter((event) => event.sequence > after && event.sequence <= record.cursor)
        .sort((left, right) => left.sequence - right.sequence);
      if (events.length !== record.cursor - after) {
        throw new LedgerConflict("command_replay_snapshot_incomplete");
      }
      return { record, events, cursor: record.cursor };
    });
  }

  async get(commandId) {
    return this.storage.get(commandKey(commandId));
  }
}

export class DurableSandboxLedger {
  constructor(storage) {
    this.storage = storage;
  }

  async ensure(identity) {
    validateSandboxIdentity(identity);
    return this.storage.transaction(async (transaction) => {
      const existing = await transaction.get("sandbox:identity");
      if (existing) {
        if (JSON.stringify(existing) !== JSON.stringify(identity)) {
          throw new LedgerConflict("sandbox_identity_conflict");
        }
        return { created: false, identity: existing };
      }
      await transaction.put("sandbox:identity", identity);
      return { created: true, identity };
    });
  }

  async get() {
    return this.storage.get("sandbox:identity");
  }
}

function validateIntent(intent) {
  if (!intent || !COMMAND_ID.test(intent.commandId ?? "")) {
    throw new LedgerConflict("command_id_invalid");
  }
  if (!SHA256.test(intent.intentDigestSha256 ?? "")) {
    throw new LedgerConflict("command_intent_digest_invalid");
  }
  for (const field of ["organizationId", "workspaceId", "sandboxId"]) {
    if (typeof intent[field] !== "string" || intent[field].length === 0) {
      throw new LedgerConflict("command_identity_invalid");
    }
  }
  if (!Array.isArray(intent.argv) || intent.argv.length === 0) {
    throw new LedgerConflict("command_argv_invalid");
  }
}

function validateSandboxIdentity(identity) {
  for (const field of ["sandboxId", "homeId", "organizationId", "workspaceId"]) {
    if (typeof identity?.[field] !== "string" || identity[field].length === 0) {
      throw new LedgerConflict("sandbox_identity_invalid");
    }
  }
}

function assertRecord(record, digest) {
  if (!record) throw new LedgerConflict("command_not_found");
  if (record.intent.intentDigestSha256 !== digest) {
    throw new LedgerConflict("command_intent_conflict");
  }
}

function assertSameIntent(existing, requested) {
  if (JSON.stringify(existing) !== JSON.stringify(requested)) {
    throw new LedgerConflict("command_intent_conflict");
  }
}

function sameTerminal(existing, requested) {
  return (
    existing.exitCode === requested.exitCode &&
    existing.stdout === requested.stdout &&
    existing.stderr === requested.stderr &&
    existing.code === requested.code
  );
}

function safeReason(reason) {
  return typeof reason === "string" && /^[a-z0-9_.-]{1,96}$/.test(reason)
    ? reason
    : "bridge_error";
}

function commandKey(commandId) {
  return `command:meta:${commandId}`;
}

function eventPrefix(commandId) {
  return `command:event:${commandId}:`;
}

function eventKey(commandId, sequence) {
  return `${eventPrefix(commandId)}${String(sequence).padStart(16, "0")}`;
}
