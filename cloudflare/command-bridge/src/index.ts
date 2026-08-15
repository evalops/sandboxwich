import { DurableObject } from "cloudflare:workers";
import { getSandbox, type Sandbox as SandboxClass } from "@cloudflare/sandbox";

import { CommandCoordinator } from "./coordinator.mjs";
import {
  BridgeContractError,
  attachIntentDigest,
  authorize,
  capabilityReport,
  jsonError,
  normalizeCommand,
  recoveryIdentityRequest,
  requestIdentity,
} from "./contract.mjs";
import { DurableCommandLedger, DurableSandboxLedger, LedgerConflict } from "./ledger.mjs";

export { ContainerProxy, Sandbox } from "@cloudflare/sandbox";

interface Env {
  Sandbox: DurableObjectNamespace<SandboxClass>;
  COMMAND_LEDGER: DurableObjectNamespace<CommandLedger>;
  DEX_COMPUTER_HOME: R2Bucket;
  BRIDGE_TOKEN: string;
  RECOVERY_TENANT: string;
  RECOVERY_SANDBOX_IDS: string;
}

interface CreateBody {
  sandboxId?: unknown;
  homeId?: unknown;
  tenantId?: unknown;
}

const OPAQUE_ID = /^[A-Za-z0-9._:-]{1,256}$/;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const bindings = capabilityReport(env);
    if (url.pathname === "/health") {
      if (!bindings.ok) return Response.json(bindings, { status: 503 });
      if (!authorize(request, env.BRIDGE_TOKEN)) return jsonError("unauthorized", 401);
      return Response.json(bindings);
    }

    if (!bindings.ok) return jsonError("command_bindings_not_configured", 503);
    if (!authorize(request, env.BRIDGE_TOKEN)) return jsonError("unauthorized", 401);

    let sandboxId: string | null = null;
    if (request.method === "POST" && url.pathname === "/v1/sandbox") {
      const body = (await request.clone().json()) as CreateBody;
      sandboxId = typeof body.sandboxId === "string" ? body.sandboxId : null;
    } else {
      sandboxId = sandboxIdFromPath(url.pathname);
    }
    if (!sandboxId || !OPAQUE_ID.test(sandboxId)) return jsonError("sandbox_id_invalid", 400);

    const durableId = env.COMMAND_LEDGER.idFromName(sandboxId);
    return env.COMMAND_LEDGER.get(durableId).fetch(request);
  },
};

export class CommandLedger extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === "POST" && url.pathname === "/v1/sandbox") {
        return await this.createSandbox(request);
      }

      const sandboxId = sandboxIdFromPath(url.pathname);
      if (!sandboxId) return jsonError("not_found", 404);
      if (request.method === "GET" && url.pathname === `/v1/sandbox/${sandboxId}/running`) {
        return await this.sandboxReady(request, sandboxId);
      }
      if (request.method === "POST" && url.pathname === `/v1/sandbox/${sandboxId}/exec`) {
        return await this.execute(request, sandboxId);
      }
      if (request.method === "GET" && url.pathname.startsWith(`/v1/sandbox/${sandboxId}/exec/`)) {
        return await this.resultLookup(request, sandboxId);
      }
      if (request.method === "DELETE" && url.pathname === `/v1/sandbox/${sandboxId}`) {
        return await this.destroySandbox(request, sandboxId);
      }
      return jsonError("not_found", 404);
    } catch (error) {
      if (error instanceof BridgeContractError) return jsonError(error.code, error.status);
      if (error instanceof LedgerConflict) {
        const status = error.code === "command_not_found" ? 404 : 409;
        return jsonError(error.code, status);
      }
      console.error("cloudflare bridge request failed", safeError(error));
      return jsonError("bridge_error", 500);
    }
  }

  private async createSandbox(request: Request): Promise<Response> {
    const body = (await request.json()) as CreateBody;
    const sandboxId = requireOpaque(body.sandboxId, "sandbox_id_invalid");
    const homeId = requireOpaque(body.homeId, "home_id_required");
    const identity = requestIdentity(request, sandboxId);
    if (body.tenantId !== `${identity.organizationId}:${identity.workspaceId}`) {
      throw new BridgeContractError("tenant_scope_mismatch", 403);
    }
    if (request.headers.get("x-sandboxwich-sandbox-id") !== sandboxId) {
      throw new BridgeContractError("sandbox_identity_mismatch", 409);
    }
    if (request.headers.get("idempotency-key") !== `sandboxwich-create-${sandboxId}`) {
      throw new BridgeContractError("create_idempotency_key_invalid", 400);
    }

    const sandboxLedger = new DurableSandboxLedger(this.ctx.storage);
    const admitted = await sandboxLedger.ensure({ ...identity, homeId });
    const sandbox = this.sandboxFor({ ...identity, homeId });
    await this.ensureHomeMounted(sandbox, { ...identity, homeId });
    return Response.json(
      { ok: true, id: sandboxId, sandboxId, homeId, created: admitted.created },
      { status: admitted.created ? 201 : 200 },
    );
  }

  private async sandboxReady(request: Request, sandboxId: string): Promise<Response> {
    const identity = await this.requireStoredIdentity(request, sandboxId);
    const sandbox = this.sandboxFor(identity);
    await sandbox.exec("test -d /home/dex && test -w /home/dex", { timeout: 10_000 });
    return Response.json({ ok: true, running: true, status: "running", sandboxId });
  }

  private async execute(request: Request, sandboxId: string): Promise<Response> {
    const identity = await this.requireStoredIdentity(request, sandboxId);
    const commandId = requireOpaque(
      request.headers.get("x-sandboxwich-command-id"),
      "command_id_invalid",
    );
    if (request.headers.get("idempotency-key") !== commandId) {
      throw new BridgeContractError("command_idempotency_key_mismatch", 409);
    }
    const body = await request.json();
    const intent = await attachIntentDigest(normalizeCommand(body, identity, commandId));
    const coordinator = new CommandCoordinator(
      new DurableCommandLedger(this.ctx.storage),
      this.sandboxFor(identity),
    );
    const result = await coordinator.execute(intent);
    return commandResponse(result);
  }

  private async resultLookup(request: Request, sandboxId: string): Promise<Response> {
    await this.requireStoredIdentity(request, sandboxId);
    const url = new URL(request.url);
    const commandId = requireOpaque(url.pathname.split("/").at(-1), "command_id_invalid");
    const ledger = new DurableCommandLedger(this.ctx.storage);
    const record = await ledger.get(commandId);
    if (!record) return jsonError("command_not_found", 404);
    const after = Number(url.searchParams.get("cursor") ?? "0");
    const result = await new CommandCoordinator(ledger, this.sandboxFor(record.intent)).lookup(
      commandId,
      record.intent.intentDigestSha256,
      after,
    );
    return commandResponse(result);
  }

  private async destroySandbox(request: Request, sandboxId: string): Promise<Response> {
    const recovery = recoveryIdentityRequest(
      request,
      sandboxId,
      this.env.RECOVERY_TENANT,
      this.env.RECOVERY_SANDBOX_IDS,
    );
    const identity = recovery
      ? await this.requireRecoveryStoredIdentity(sandboxId)
      : await this.requireStoredIdentity(request, sandboxId);
    await this.sandboxFor(identity).destroy();
    await this.ctx.storage.delete("sandbox:home-mounted");
    return Response.json({ ok: true, sandboxId });
  }

  private async requireRecoveryStoredIdentity(sandboxId: string) {
    const stored = await new DurableSandboxLedger(this.ctx.storage).get();
    if (!stored) throw new BridgeContractError("sandbox_not_found", 404);
    if (stored.sandboxId !== sandboxId) {
      throw new BridgeContractError("sandbox_identity_conflict", 409);
    }
    return stored;
  }

  private async requireStoredIdentity(request: Request, sandboxId: string) {
    const requested = requestIdentity(request, sandboxId);
    const stored = await new DurableSandboxLedger(this.ctx.storage).get();
    if (!stored) throw new BridgeContractError("sandbox_not_found", 404);
    if (
      stored.sandboxId !== requested.sandboxId ||
      stored.organizationId !== requested.organizationId ||
      stored.workspaceId !== requested.workspaceId
    ) {
      throw new BridgeContractError("sandbox_identity_conflict", 409);
    }
    return stored;
  }

  private sandboxFor(identity: {
    sandboxId: string;
    organizationId: string;
    workspaceId: string;
    homeId?: string;
  }) {
    return getSandbox(this.env.Sandbox, identity.sandboxId, {
      sleepAfter: "10m",
      enableDefaultSession: false,
      normalizeId: true,
      labels: { workload: "dex-computer", provider: "sandboxwich" },
    });
  }

  private async ensureHomeMounted(
    sandbox: ReturnType<typeof getSandbox>,
    identity: { organizationId: string; workspaceId: string; homeId: string },
  ) {
    if (await this.ctx.storage.get<boolean>("sandbox:home-mounted")) return;
    const scopeHash = await sha256(`${identity.organizationId}\0${identity.workspaceId}`);
    try {
      await sandbox.mountBucket("DEX_COMPUTER_HOME", "/home/dex", {
        prefix: `/dex-computers/${scopeHash}/${identity.homeId}/`,
      });
    } catch (error) {
      const message = safeError(error).toLowerCase();
      if (!(message.includes("mount") && message.includes("already"))) throw error;
    }
    await sandbox.exec("mkdir -p /home/dex/threads", { timeout: 10_000 });
    await this.ctx.storage.put("sandbox:home-mounted", true);
  }
}

function commandResponse(result: {
  status: string;
  record?: { cursor?: number; terminal?: unknown };
  events?: Array<{ name: string; value?: string; exitCode?: number; code?: string }>;
  cursor?: number;
}) {
  if (result.status === "completed" || result.status === "failed") {
    const chunks = (result.events ?? []).map((event) => {
      if (event.name === "stdout" || event.name === "stderr") {
        return `event: ${event.name}\ndata: ${event.value ?? ""}\n\n`;
      }
      if (event.name === "exit") {
        return `event: exit\ndata: ${JSON.stringify({ exit_code: event.exitCode })}\n\n`;
      }
      return `event: error\ndata: ${JSON.stringify({ code: event.code ?? "command_failed" })}\n\n`;
    });
    return new Response(chunks.join(""), {
      status: 200,
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store",
        "x-command-cursor": String(result.cursor ?? result.record?.cursor ?? 0),
      },
    });
  }
  if (result.status === "indeterminate") return jsonError("command_indeterminate", 503);
  if (result.status === "not_found") return jsonError("command_not_found", 404);
  return jsonError("command_in_progress", 409);
}

function sandboxIdFromPath(pathname: string) {
  const match = /^\/v1\/sandbox\/([^/]+)(?:\/|$)/.exec(pathname);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

function requireOpaque(value: unknown, code: string) {
  if (typeof value !== "string" || !OPAQUE_ID.test(value)) {
    throw new BridgeContractError(code, 400);
  }
  return value;
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function safeError(error: unknown) {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}
