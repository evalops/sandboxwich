#!/usr/bin/env python3
"""Static and structural authorization proof gate for one repository."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "docs" / "authorization" / "authz-conformance.v1.json"


def normalize_route(path: str) -> str | None:
    if path == "/v1":
        return None
    if path.startswith("/v1/"):
        path = path[3:]
    if path == "/tenant-policies/{tenant_id}":
        path = "/operator" + path
    return re.sub(r"\{[^}]+\}", "*", path)


def main() -> int:
    errors: list[str] = []
    try:
        fixture = json.loads(FIXTURE_PATH.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"AUTHZ_PROOF hard_gate_failures=1 error=fixture:{error}")
        return 1

    if fixture.get("schema") != "authz_conformance_v1":
        errors.append("fixture schema is not authz_conformance_v1")
    if fixture.get("version") != 1:
        errors.append("fixture version is not 1")

    hard_gates = fixture.get("hard_gates")
    if not isinstance(hard_gates, dict):
        errors.append("hard_gates must be an object")
    else:
        for name, value in hard_gates.items():
            if not isinstance(value, int) or value != 0:
                errors.append(f"hard gate {name} must be zero")

    evidence_fields = fixture.get("evidence_fields")
    if not isinstance(evidence_fields, dict):
        errors.append("evidence_fields must be an object")
        evidence_fields = {}

    cases = fixture.get("cases")
    if not isinstance(cases, list) or not cases:
        errors.append("cases must be a non-empty array")
        cases = []
    case_ids = [case.get("id") for case in cases if isinstance(case, dict)]
    if len(case_ids) != len(set(case_ids)):
        errors.append("case IDs must be unique")
    valid_effects = {"allow", "deny", "require_approval"}
    valid_reasons = {
        "allowed",
        "unknown_route",
        "route_not_exposed",
        "principal_class_not_allowed",
        "organization_mismatch",
        "delegation_narrowed",
        "approval_required",
    }
    for case in cases:
        if not isinstance(case, dict):
            errors.append("every case must be an object")
            continue
        if case.get("engine") not in {"platform", "sandboxwich"}:
            errors.append(f"unknown engine for case {case.get('id')!r}")
        if case.get("expected_effect") not in valid_effects:
            errors.append(f"invalid expected effect for case {case.get('id')!r}")
        if case.get("expected_reason") not in valid_reasons:
            errors.append(f"invalid expected reason for case {case.get('id')!r}")

    forbidden_fields = (
        "tenantid",
        "workspaceid",
        "teamid",
        "environmentid",
        "sandboxid",
        "workerid",
        "secret",
        "token",
    )
    for engine, fields in evidence_fields.items():
        if not isinstance(fields, list):
            errors.append(f"evidence fields for {engine} must be an array")
            continue
        for field in fields:
            lowered = str(field).lower()
            if any(forbidden in lowered for forbidden in forbidden_fields):
                errors.append(f"evidence field {engine}.{field} could leak a raw identifier")
        if "lineageId" not in fields:
            errors.append(f"evidence fields for {engine} omit lineageId")

    platform_root = ROOT / "rust" / "crates" / "authorization-core"
    route_coverage = "n/a"
    if platform_root.exists():
        source = (platform_root / "src" / "lib.rs").read_text()
        tests = (platform_root / "tests" / "authorization.rs").read_text()
        for fragment in (
            "AuthorizationLineageId",
            "DecisionKind",
            "DecisionReason",
            "DelegationExpansion",
            "authorization_fingerprint",
            "AUTHZ_TRACE_TARGET",
        ):
            if fragment not in source:
                errors.append(f"platform source missing {fragment}")
        for fragment in (
            "organization_boundary_is_checked_before_role_matching",
            "delegation_blocks_permissions_outside_the_narrowed_set",
            "owner_and_approval_obligations_are_enforced",
            "authorization_fingerprint_is_stable_across_transport_attempts",
        ):
            if fragment not in tests:
                errors.append(f"platform proof test missing {fragment}")
        platform_cases = [case for case in cases if case.get("engine") == "platform"]
        if len(platform_cases) < 3:
            errors.append("platform conformance cases are incomplete")
    else:
        authz_path = ROOT / "crates" / "sandboxwich-api" / "src" / "authz.rs"
        routes_path = ROOT / "crates" / "sandboxwich-api" / "src" / "routes.rs"
        try:
            authz_source = authz_path.read_text()
            routes_source = routes_path.read_text()
        except OSError as error:
            errors.append(f"sandboxwich source unavailable: {error}")
            authz_source = ""
            routes_source = ""
        for fragment in (
            "PrincipalRequirement::Deny",
            "AUTHORIZATION_ROUTE_MANIFEST",
            "AUTHORIZATION_NON_TENANT_ROUTE_MANIFEST",
            "authorization_fingerprint",
            "receipt_id",
            "AUTHORIZATION_LINEAGE_ID_HEADER",
        ):
            if fragment not in authz_source:
                errors.append(f"sandboxwich authz source missing {fragment}")
        if "default|tenant_or_operator|*" in authz_source:
            errors.append("sandboxwich authorization policy has an implicit allow-all default")
        route_literals = re.findall(r'\.route\(\s*"([^"]+)"', routes_source, re.S)
        manifest_match = re.search(
            r"const AUTHORIZATION_ROUTE_MANIFEST:.*?= &\[(.*?)\];",
            authz_source,
            re.S,
        )
        manifest = (
            set(re.findall(r'"([^"]+)"', manifest_match.group(1)))
            if manifest_match
            else set()
        )
        normalized_routes = {
            normalized
            for literal in route_literals
            if (normalized := normalize_route(literal)) is not None
        }
        missing_routes = sorted(normalized_routes - manifest)
        if missing_routes:
            errors.append(
                "sandboxwich route manifest misses: " + ", ".join(missing_routes)
            )
        route_coverage = f"{len(normalized_routes) - len(missing_routes)}/{len(normalized_routes)}"
        sandbox_cases = [case for case in cases if case.get("engine") == "sandboxwich"]
        if len(sandbox_cases) < 5:
            errors.append("sandboxwich conformance cases are incomplete")

    summary = (
        f"AUTHZ_PROOF schema={fixture.get('schema')} "
        f"cases={len(cases)} evidence_engines={len(evidence_fields)} "
        f"route_coverage={route_coverage} raw_identifier_fields=0 "
        f"hard_gate_failures={len(errors)}"
    )
    print(summary)
    for error in errors:
        print(f"AUTHZ_PROOF_ERROR {error}", file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
