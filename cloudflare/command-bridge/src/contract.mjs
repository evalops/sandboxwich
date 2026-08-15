const OPAQUE_ID = /^[A-Za-z0-9._:-]{1,256}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function capabilityReport(env) {
  const ledger = Boolean(env?.COMMAND_LEDGER);
  const sandbox = Boolean(env?.Sandbox);
  const home = Boolean(env?.DEX_COMPUTER_HOME);
  const token = typeof env?.BRIDGE_TOKEN === "string" && env.BRIDGE_TOKEN.length >= 24;
  const recoveryTenant =
    typeof env?.RECOVERY_TENANT === "string" && OPAQUE_ID.test(env.RECOVERY_TENANT);
  const command = ledger && sandbox && home && token && recoveryTenant;
  return {
    ok: command,
    durableLedger: ledger,
    sandboxBinding: sandbox,
    homeBinding: home,
    tokenBinding: token,
    recoveryTenantBinding: recoveryTenant,
    capabilities: command ? ["sandbox.create", "sandbox.exec", "sandbox.result-replay"] : [],
  };
}

export function authorize(request, token) {
  const supplied = request.headers.get("authorization") ?? "";
  const expected = `Bearer ${token}`;
  if (supplied.length !== expected.length) return false;
  let difference = 0;
  for (let index = 0; index < supplied.length; index += 1) {
    difference |= supplied.charCodeAt(index) ^ expected.charCodeAt(index);
  }
  return difference === 0;
}

export function requestIdentity(request, sandboxId) {
  const organizationId = request.headers.get("x-organization-id") ?? "";
  const workspaceId = request.headers.get("x-workspace-id") ?? "";
  if (![organizationId, workspaceId, sandboxId].every((value) => OPAQUE_ID.test(value))) {
    throw new BridgeContractError("sandbox_identity_invalid", 400);
  }
  return { organizationId, workspaceId, sandboxId };
}

export function recoveryIdentityRequest(request, sandboxId, recoveryTenant) {
  if (request.headers.get("x-sandboxwich-recover-identity") !== "stored") return null;
  if (request.headers.get("x-sandboxwich-sandbox-id") !== sandboxId) {
    throw new BridgeContractError("sandbox_identity_mismatch", 409);
  }
  const tenantHint = request.headers.get("x-sandboxwich-recovery-tenant") ?? "";
  if (!OPAQUE_ID.test(tenantHint)) {
    throw new BridgeContractError("recovery_tenant_invalid", 400);
  }
  if (tenantHint !== recoveryTenant) {
    throw new BridgeContractError("recovery_tenant_mismatch", 403);
  }
  return { tenantHint };
}

export function normalizeCommand(body, identity, commandId) {
  if (!OPAQUE_ID.test(commandId)) throw new BridgeContractError("command_id_invalid", 400);
  if (!body || !Array.isArray(body.argv) || body.argv.length === 0 || body.argv.length > 256) {
    throw new BridgeContractError("command_argv_invalid", 400);
  }
  const argv = body.argv.map((value) => boundedString(value, 16_384, "command_argv_invalid"));
  const cwd = body.cwd == null ? "/home/dex" : boundedString(body.cwd, 1_024, "command_cwd_invalid");
  if (cwd !== "/home/dex" && !cwd.startsWith("/home/dex/threads/")) {
    throw new BridgeContractError("command_cwd_outside_home", 400);
  }
  if (cwd.split("/").includes("..")) throw new BridgeContractError("command_cwd_outside_home", 400);
  const env = {};
  for (const key of Object.keys(body.env ?? {}).sort()) {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key)) {
      throw new BridgeContractError("command_env_invalid", 400);
    }
    env[key] = boundedString(body.env[key], 16_384, "command_env_invalid");
  }
  const stdinBase64 = body.stdin == null ? null : boundedString(body.stdin, 1_398_104, "command_stdin_invalid");
  if (stdinBase64 !== null && (!BASE64.test(stdinBase64) || decodedLength(stdinBase64) > 1_048_576)) {
    throw new BridgeContractError("command_stdin_invalid", 400);
  }
  const timeoutSeconds = body.timeout_secs == null ? 30 : Number(body.timeout_secs);
  if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 900) {
    throw new BridgeContractError("command_timeout_invalid", 400);
  }
  return {
    commandId,
    ...identity,
    argv,
    cwd,
    env,
    stdinBase64,
    timeoutSeconds,
  };
}

export async function attachIntentDigest(intent) {
  const bytes = new TextEncoder().encode(JSON.stringify(intent));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  intent.intentDigestSha256 = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return intent;
}

export function jsonError(code, status = 500) {
  return Response.json({ ok: false, code }, { status });
}

export class BridgeContractError extends Error {
  constructor(code, status) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function boundedString(value, maximum, code) {
  if (typeof value !== "string" || value.length > maximum || value.includes("\0")) {
    throw new BridgeContractError(code, 400);
  }
  return value;
}

function decodedLength(value) {
  if (value.length === 0) return 0;
  return (value.length * 3) / 4 - (value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0);
}
