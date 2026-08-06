export class CommandCoordinator {
  constructor(ledger, sandbox, options = {}) {
    this.ledger = ledger;
    this.sandbox = sandbox;
    this.dispatchLeaseMs = options.dispatchLeaseMs ?? 5_000;
  }

  async execute(intent) {
    const admission = await this.ledger.admit(intent);
    const { record } = admission;

    if (record.terminal) return this.lookup(intent.commandId, intent.intentDigestSha256, 0);

    if (!admission.accepted) {
      if (record.state === "accepted") return this.#dispatch(intent);
      if (record.state === "dispatching") {
        const age = Date.now() - (record.dispatchedAt ?? Date.now());
        if (age < this.dispatchLeaseMs) return response(record.state, record);
      }
      return this.reconcile(intent);
    }

    return this.#dispatch(intent);
  }

  async reconcile(intent) {
    const record = await this.ledger.get(intent.commandId);
    if (!record) return { status: "not_found" };
    if (record.intent.intentDigestSha256 !== intent.intentDigestSha256) {
      return this.lookup(intent.commandId, intent.intentDigestSha256, 0);
    }
    if (record.terminal) return this.lookup(intent.commandId, intent.intentDigestSha256, 0);
    if (record.state === "accepted") return response("accepted", record);

    const process = await this.sandbox.getProcess(intent.commandId);
    if (!process) {
      const indeterminate = await this.ledger.markIndeterminate(
        intent.commandId,
        intent.intentDigestSha256,
        "process_not_observable",
      );
      return response("indeterminate", indeterminate);
    }

    await this.ledger.markRunning(intent.commandId, intent.intentDigestSha256);
    return this.#collect(intent, process, false);
  }

  async lookup(commandId, digest, after = 0) {
    const replay = await this.ledger.replay(commandId, digest, after);
    return {
      status: replay.record.terminal ? replay.record.state : replay.record.state,
      ...replay,
    };
  }

  async #dispatch(intent) {
    const claimed = await this.ledger.claimDispatch(
      intent.commandId,
      intent.intentDigestSha256,
    );
    if (!claimed) {
      const record = await this.ledger.get(intent.commandId);
      return response(record.state, record);
    }

    try {
      const process = await this.sandbox.startProcess(commandFor(intent), {
        processId: intent.commandId,
        autoCleanup: false,
        cwd: intent.cwd || undefined,
        env: intent.env || undefined,
        timeout: timeoutMilliseconds(intent.timeoutSeconds),
      });
      await this.ledger.markRunning(intent.commandId, intent.intentDigestSha256);
      return this.#collect(intent, process, true);
    } catch (_error) {
      const process = await this.sandbox.getProcess(intent.commandId);
      if (process) {
        await this.ledger.markRunning(intent.commandId, intent.intentDigestSha256);
        return this.#collect(intent, process, true);
      }
      const record = await this.ledger.markIndeterminate(
        intent.commandId,
        intent.intentDigestSha256,
        "dispatch_response_lost",
      );
      return response("indeterminate", record);
    }
  }

  async #collect(intent, process, wait) {
    const status = await process.getStatus();
    if (!wait && (status === "starting" || status === "running")) {
      return response("in_progress", await this.ledger.get(intent.commandId));
    }

    let exitCode;
    try {
      ({ exitCode } = await process.waitForExit(timeoutMilliseconds(intent.timeoutSeconds)));
    } catch (_error) {
      const current = await process.getStatus();
      if (current === "starting" || current === "running") {
        return response("in_progress", await this.ledger.get(intent.commandId));
      }
      exitCode = process.exitCode ?? 1;
    }

    const logs = await process.getLogs();
    if (logs.stdout) {
      await this.ledger.append(intent.commandId, intent.intentDigestSha256, {
        name: "stdout",
        value: toBase64(logs.stdout),
      });
    }
    if (logs.stderr) {
      await this.ledger.append(intent.commandId, intent.intentDigestSha256, {
        name: "stderr",
        value: toBase64(logs.stderr),
      });
    }
    const record = await this.ledger.complete(intent.commandId, intent.intentDigestSha256, {
      exitCode,
      stdout: logs.stdout,
      stderr: logs.stderr,
    });
    return this.lookup(intent.commandId, intent.intentDigestSha256, 0).then((result) => ({
      ...result,
      record,
    }));
  }
}

function response(status, record) {
  return { status: status === "dispatching" || status === "running" ? "in_progress" : status, record };
}

function timeoutMilliseconds(seconds) {
  return Number.isFinite(seconds) && seconds > 0 ? Math.floor(seconds * 1_000) : undefined;
}

function commandFor(intent) {
  const command = intent.argv.map(shellQuote).join(" ");
  if (typeof intent.stdinBase64 !== "string" || intent.stdinBase64.length === 0) return command;
  return `printf %s ${shellQuote(intent.stdinBase64)} | base64 -d | ${command}`;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'\\''`)}'`;
}

function toBase64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8_192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8_192));
  }
  return btoa(binary);
}
