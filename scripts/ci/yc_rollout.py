"""Prepare, verify and switch ID backends without modifying the serving slot."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

SLOTS = {
    "blue": "yandex_serverless_container.backend",
    "green": "yandex_serverless_container.backend_green[0]",
}
GATEWAYS = {"terraform_data.existing_gateway_spec[0]", "yandex_api_gateway.id[0]"}
RECREATABLE = {"terraform_data", "yandex_lockbox_secret_version"}


def read_json(*command: str) -> Any:
    return json.loads(subprocess.check_output(command, text=True))


def write_private(path: Path, value: Any) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)


def gateway_backend(spec: str) -> str:
    document = yaml.safe_load(spec)
    expected = (
        "/api/v1/{proxy+}",
        "/oauth/{proxy+}",
        "/.well-known/{proxy+}",
        "/health",
        "/healthz",
        "/readyz",
    )
    targets = set()
    for path in expected:
        route = document.get("paths", {}).get(path, {})
        integrations = [
            operation.get("x-yc-apigateway-integration", {})
            for operation in route.values()
            if isinstance(operation, dict)
        ]
        targets.update(
            item.get("container_id")
            for item in integrations
            if item.get("type") == "serverless_containers"
        )
        if (
            len(
                [
                    item
                    for item in integrations
                    if item.get("type") == "serverless_containers"
                ]
            )
            != 1
        ):
            raise RuntimeError(f"Expected one container integration for {path}")
    if len(targets) != 1 or None in targets:
        raise RuntimeError(
            "Backend routes must consistently target one known container"
        )
    return targets.pop()


def active_revision(container_id: str) -> dict[str, Any]:
    revisions = read_json(
        "yc",
        "serverless",
        "container",
        "revision",
        "list",
        "--container-id",
        container_id,
        "--format",
        "json",
    )
    active = [revision for revision in revisions if revision["status"] == "ACTIVE"]
    if len(active) != 1:
        raise RuntimeError("Expected one active revision for the selected backend")
    return active[0]


def revision_config(revision: dict[str, Any]) -> dict[str, Any]:
    image = revision["image"]
    if (
        any(image.get(key) for key in ("command", "args", "work_dir"))
        or revision.get("scaling_policy")
        or revision.get("storage_mounts")
        or revision.get("mounts")
    ):
        raise RuntimeError(
            "Custom command/scaling/mounts require explicit rollout support; refusing to lose live configuration"
        )
    if "http" not in revision.get("runtime", {}):
        raise RuntimeError("Only HTTP backend revisions can be retained")
    resources = revision["resources"]
    endpoint_modes = {
        "ENABLED": 1,
        "DISABLED": 2,
        "METADATA_ENDPOINT_DISABLED": 2,
        "METADATA_ENDPOINT_ENABLED": 1,
        "METADATA_ENDPOINT_UNSPECIFIED": 0,
    }

    def endpoint(value: Any) -> int:
        return endpoint_modes[value] if value in endpoint_modes else int(value)

    metadata = revision.get("metadata_options", {})
    return {
        "image_url": image["image_url"],
        "environment": image.get("environment", {}),
        "memory": int(resources["memory"]) // (1024 * 1024),
        "cores": int(resources["cores"]),
        "core_fraction": int(resources.get("core_fraction", 100)),
        "concurrency": int(revision["concurrency"]),
        "execution_timeout": revision["execution_timeout"],
        "service_account_id": revision["service_account_id"],
        "network_id": revision.get("connectivity", {}).get("network_id", ""),
        "min_instances": int(
            revision.get("provision_policy", {}).get("min_instances", 0)
        ),
        "log_group_id": revision["log_options"]["log_group_id"],
        "log_min_level": revision["log_options"].get("min_level", "INFO"),
        "metadata_options": {
            "gce_http_endpoint": endpoint(metadata.get("gce_http_endpoint", 0)),
            "aws_v1_http_endpoint": endpoint(metadata.get("aws_v1_http_endpoint", 0)),
        },
        "secrets": revision.get("secrets", []),
    }


def rollout_snapshot(
    outputs: dict[str, Any], release_tag: str
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", release_tag):
        raise RuntimeError("Invalid release image tag")
    legacy_id = urlparse(outputs["backend_invoke_url"]["value"]).hostname.split(".", 1)[
        0
    ]
    slots = outputs.get("backend_slots", {}).get("value", {"ids": {"blue": legacy_id}})
    gateway_id = outputs["api_gateway_id"]["value"]
    gateway = read_json(
        "yc",
        "serverless",
        "api-gateway",
        "get-spec",
        "--id",
        gateway_id,
        "--format",
        "json",
    )
    spec = gateway["openapi_spec"]
    container_id = gateway_backend(spec)
    matching = [
        slot for slot, identity in slots["ids"].items() if identity == container_id
    ]
    if len(matching) != 1:
        raise RuntimeError(
            "Live gateway targets a backend outside this Terraform stack"
        )
    original = matching[0]
    target = "green" if original == "blue" else "blue"
    revision = active_revision(container_id)
    overrides = {
        "rollout_active_slot": original,
        "rollout_target_slot": target,
        "retained_backend_config": revision_config(revision),
    }
    manifest = {
        "original_slot": original,
        "target_slot": target,
        "gateway_id": gateway_id,
        "gateway_spec_before": spec,
        "original_container_id": container_id,
        "original_revision_id": revision["id"],
        "retained_secret_versions": sorted(
            {secret["version_id"] for secret in revision.get("secrets", [])}
        ),
        "release_tag": release_tag,
        "promotion_attempted": False,
        "preparation_started": False,
    }
    return container_id, overrides, manifest


def adds_sensitive_marks(before: Any, after: Any) -> bool:
    if after is True:
        return True
    if before is True:
        return False
    if isinstance(before, dict):
        return isinstance(after, dict) and all(
            adds_sensitive_marks(value, after.get(key)) for key, value in before.items()
        )
    if isinstance(before, list):
        return (
            isinstance(after, list)
            and len(before) == len(after)
            and all(adds_sensitive_marks(a, b) for a, b in zip(before, after))
        )
    return True


def has_unknown(value: Any) -> bool:
    if isinstance(value, dict):
        return any(has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(has_unknown(item) for item in value)
    return value is True


def sensitivity_only(change: dict[str, Any]) -> bool:
    # Terraform 1.15.7 does not call ApplyResourceChange when only marks change:
    # https://github.com/hashicorp/terraform/blob/v1.15.7/internal/terraform/node_resource_abstract_instance.go#L2644
    # Preserve/add sensitivity; never allow unknown or changed runtime values.
    return (
        change["actions"] == ["update"]
        and change.get("before") is not None
        and not has_unknown(change.get("after_unknown"))
        and json.dumps(change["before"], sort_keys=True)
        == json.dumps(change["after"], sort_keys=True)
        and change.get("before_sensitive") != change.get("after_sensitive")
        and adds_sensitive_marks(
            change.get("before_sensitive"), change.get("after_sensitive")
        )
    )


def validate_plan(plan: dict[str, Any], manifest: dict[str, Any], phase: str) -> None:
    if phase not in {"prepare", "promote", "rollback", "retire", "abort"}:
        raise RuntimeError("Unknown rollout phase")
    original = SLOTS[manifest["original_slot"]]
    target = SLOTS[manifest["target_slot"]]
    for item in plan.get("resource_changes", []):
        if item.get("mode") == "data":
            continue
        actions = item["change"]["actions"]
        address = item["address"]
        if actions == ["no-op"] or sensitivity_only(item["change"]):
            continue
        if "delete" in actions and item["type"] not in RECREATABLE:
            raise RuntimeError(f"Refusing destructive resource change: {address}")
        if phase == "prepare":
            if (
                item["type"] == "yandex_lockbox_secret_version"
                and "delete" in actions
                and (item["change"].get("before") or {}).get("id")
                in manifest.get("retained_secret_versions", [])
            ):
                raise RuntimeError(
                    "Preparation cannot delete a secret version still used by the serving backend"
                )
            if address == original or address in GATEWAYS:
                raise RuntimeError(
                    f"Preparation would change the serving backend or gateway: {address}"
                )
        elif phase in {"promote", "rollback"}:
            if address not in GATEWAYS:
                raise RuntimeError(
                    f"Switching traffic must not change runtime resources: {address}"
                )
        elif phase in {"retire", "abort"}:
            allowed = original if phase == "retire" else target
            if address != allowed or actions != ["update"]:
                raise RuntimeError(
                    f"Capacity cleanup may only update the inactive backend: {address}"
                )
            before, after = item["change"]["before"], item["change"]["after"]
            if any(
                policy.get("min_instances") != 0
                for policy in after.get("provision_policy", []) or []
            ):
                raise RuntimeError(
                    "Capacity cleanup may only disable prepared capacity"
                )
            for key in (
                "name",
                "description",
                "labels",
                "runtime",
                "async_invocation",
                "mounts",
                "storage_mounts",
                "memory",
                "cores",
                "core_fraction",
                "concurrency",
                "execution_timeout",
                "service_account_id",
                "connectivity",
                "metadata_options",
                "secrets",
                "log_options",
            ):
                if before.get(key) != after.get(key):
                    raise RuntimeError(
                        f"Capacity cleanup would change {key}: {address}"
                    )
            # Image digests/revision IDs may be computed, but image configuration must stay identical.
            for key in ("url", "environment", "command", "args", "work_dir"):
                if before["image"][0].get(key) != after["image"][0].get(key):
                    raise RuntimeError(
                        f"Capacity cleanup would change image {key}: {address}"
                    )
        else:
            raise RuntimeError("Unknown rollout phase")


def outputs(terraform_dir: Path) -> dict[str, Any]:
    return read_json("terraform", f"-chdir={terraform_dir}", "output", "-json")


def slot_ids(terraform_dir: Path) -> dict[str, str]:
    # A failed first apply may persist resources without persisting new outputs.
    current = outputs(terraform_dir).get("backend_slots", {}).get("value")
    if current:
        return current["ids"]
    state = read_json("terraform", f"-chdir={terraform_dir}", "show", "-json")
    resources = state.get("values", {}).get("root_module", {}).get("resources", [])
    return {
        slot: item["values"]["id"]
        for slot, address in SLOTS.items()
        for item in resources
        if item["address"] == address and item.get("values", {}).get("id")
    }


def target_identity(terraform_dir: Path, manifest: dict[str, Any]) -> tuple[str, str]:
    slots = outputs(terraform_dir)["backend_slots"]["value"]
    target = manifest["target_slot"]
    if not slots["enabled"] or slots["target_slot"] != target:
        raise RuntimeError("Terraform target differs from the release manifest")
    identity, url = slots["ids"][target], slots["urls"][target]
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != f"{identity}.containers.yandexcloud.net"
        or parsed.username
        or parsed.password
        or parsed.port
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RuntimeError("Refusing to send an IAM token to an unexpected endpoint")
    revision = active_revision(identity)
    if not revision["image"]["image_url"].endswith(":" + manifest["release_tag"]):
        raise RuntimeError("Candidate does not contain this release image")
    return identity, url


def verify_candidate(terraform_dir: Path, manifest: dict[str, Any]) -> None:
    identity, _ = target_identity(terraform_dir, manifest)
    revision = active_revision(identity)
    if revision["id"] != manifest.get("verified_revision_id"):
        raise RuntimeError("Candidate changed after readiness checks")
    gateway = read_json(
        "yc",
        "serverless",
        "api-gateway",
        "get-spec",
        "--id",
        manifest["gateway_id"],
        "--format",
        "json",
    )
    if gateway_backend(gateway["openapi_spec"]) != manifest[
        "original_container_id"
    ] or yaml.safe_load(gateway["openapi_spec"]) != yaml.safe_load(
        manifest["gateway_spec_before"]
    ):
        raise RuntimeError(
            "Gateway changed during preparation; refusing to overwrite it"
        )


def warm_candidate(terraform_dir: Path, manifest_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text())
    identity, url = target_identity(terraform_dir, manifest)
    revision = active_revision(identity)
    revision_id = revision["id"]
    created = datetime.fromisoformat(revision["created_at"].replace("Z", "+00:00"))
    # YC allows up to five minutes for prepared-capacity settings to take effect.
    prepared_instances = int(
        revision.get("provision_policy", {}).get("min_instances", 0)
    )
    settle_seconds = (
        max(0, 300 - (datetime.now(timezone.utc) - created).total_seconds())
        if prepared_instances > 0
        else 0
    )
    if settle_seconds:
        print(
            f"Waiting {settle_seconds:.0f}s for candidate prepared capacity; old backend is serving",
            flush=True,
        )
        time.sleep(settle_seconds)
    token = subprocess.check_output(["yc", "iam", "create-token"], text=True).strip()
    host = urlparse(url).hostname
    deadline = time.monotonic() + 300

    def probe(_: int) -> list[dict[str, Any]]:
        connection = http.client.HTTPSConnection(host, timeout=15)
        timings = []
        try:
            for path in ("/readyz", "/api/v1/auth/form_token?purpose=login"):
                started = time.monotonic()
                connection.request(
                    "GET",
                    path,
                    headers={
                        "Authorization": "Bearer " + token,
                        "X-Forwarded-Proto": "https",
                        "User-Agent": "UpdSpace-ID-release-readiness",
                    },
                )
                response = connection.getresponse()
                payload = json.loads(response.read(64 * 1024))
                if (
                    response.status != 200
                    or (path == "/readyz" and payload.get("status") != "ready")
                    or (path != "/readyz" and not payload.get("form_token"))
                ):
                    raise RuntimeError("Candidate readiness check failed")
                timings.append(
                    {
                        "path": path.split("?", 1)[0],
                        "total_ms": round((time.monotonic() - started) * 1000, 2),
                    }
                )
        finally:
            connection.close()
        return timings

    successful_rounds = 0
    while time.monotonic() < deadline:
        try:
            with ThreadPoolExecutor(max_workers=4) as executor:
                rows = list(executor.map(probe, range(4)))
            successful_rounds += 1
            print(
                json.dumps({"readiness_round": successful_rounds, "samples": rows}),
                flush=True,
            )
            if successful_rounds == 2:
                break
        except (OSError, http.client.HTTPException, ValueError, RuntimeError):
            successful_rounds = 0
            print(
                "Candidate not ready; public traffic remains on the previous backend",
                flush=True,
            )
        time.sleep(3)
    else:
        raise RuntimeError("Candidate readiness deadline exceeded")
    if active_revision(identity)["id"] != revision_id:
        raise RuntimeError("Candidate changed while readiness was being checked")
    manifest["verified_revision_id"] = revision_id
    manifest["candidate_container_id"] = identity
    write_private(manifest_path, manifest)


def run_terraform(command: list[str], log_path: Path) -> None:
    # Plans can include manually configured environment values. Raw CLI output
    # remains private on this runner alongside the saved binary plan.
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raw = log_path.read_text(errors="replace")
        # Never copy provider diagnostics to CI: they can contain runtime values.
        # Emit only fixed classifications, not matched text or response bodies.
        if "serverless.containers.count" in raw:
            print(
                "Serverless container count quota exhausted (serverless.containers.count).",
                flush=True,
            )
        elif "ResourceExhausted" in raw:
            print(
                "Cloud resource quota exhausted; inspect the deployment quotas.",
                flush=True,
            )
        elif "PermissionDenied" in raw:
            print("Cloud API denied a deployment permission.", flush=True)
        elif "Resource postcondition failed" in raw:
            print(
                "Cloud revision verification failed; requested runtime was not activated.",
                flush=True,
            )
        raise RuntimeError(f"Terraform failed; private diagnostics: {log_path}")


def apply_phase(terraform_dir: Path, manifest_path: Path, phase: str) -> None:
    manifest = json.loads(manifest_path.read_text())
    if phase == "rollback" and not manifest.get("promotion_attempted"):
        print("No gateway promotion was attempted; no rollback needed")
        return
    if phase == "abort" and not manifest.get("preparation_started"):
        print("Candidate preparation was not started; no capacity cleanup needed")
        return
    if phase == "promote":
        verify_candidate(terraform_dir, manifest)
    if phase in {"retire", "abort", "rollback"} and manifest.get("preparation_started"):
        current = read_json(
            "yc",
            "serverless",
            "api-gateway",
            "get-spec",
            "--id",
            manifest["gateway_id"],
            "--format",
            "json",
        )
        serving = gateway_backend(current["openapi_spec"])
        original = manifest["original_container_id"]
        candidate = slot_ids(terraform_dir).get(manifest["target_slot"])
        if phase == "abort" and candidate is None:
            if serving != original:
                raise RuntimeError("Gateway changed while candidate creation failed")
            print("Candidate container was not created; no capacity cleanup needed")
            return
        permitted = (
            {candidate}
            if phase == "retire"
            else ({original} if phase == "abort" else {original, candidate})
        )
        if serving not in permitted:
            raise RuntimeError(
                "Refusing cleanup/rollback while gateway targets an unexpected backend"
            )
    active = (
        manifest["target_slot"]
        if phase in {"promote", "retire"}
        else manifest["original_slot"]
    )
    private_dir = manifest_path.parent
    plan_file = private_dir / f"id-{phase}.tfplan"
    args = ["terraform", f"-chdir={terraform_dir}"]
    variables = [
        "-var-file=production.performance.tfvars",
        f"-var=rollout_active_slot={active}",
        f"-var=retire_other_backend={'true' if phase == 'retire' else 'false'}",
    ]
    if phase == "abort":
        variables.append("-var=candidate_min_ready_instances=0")
    run_terraform(
        [*args, "plan", *variables, f"-out={plan_file}"],
        private_dir / f"id-{phase}-plan.log",
    )
    plan = read_json(*args, "show", "-json", str(plan_file))
    validate_plan(plan, manifest, phase)
    print(
        json.dumps(
            {
                "phase": phase,
                "changes": [
                    {
                        "address": item["address"],
                        "actions": item["change"]["actions"],
                        "sensitivity_only": sensitivity_only(item["change"]),
                    }
                    for item in plan.get("resource_changes", [])
                    if item.get("mode") != "data"
                    and item["change"]["actions"] != ["no-op"]
                ],
            }
        ),
        flush=True,
    )
    if phase == "promote":
        manifest["promotion_attempted"] = True
    elif phase == "prepare":
        manifest["preparation_started"] = True
    write_private(manifest_path, manifest)
    if phase == "promote":
        verify_candidate(terraform_dir, manifest)
    run_terraform(
        [*args, "apply", "-auto-approve", str(plan_file)],
        private_dir / f"id-{phase}-apply.log",
    )
    print(f"Completed guarded rollout phase: {phase}", flush=True)
    manifest["last_completed_phase"] = phase
    write_private(manifest_path, manifest)


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase", choices=("prepare", "warm", "promote", "retire", "rollback", "abort")
    )
    parser.add_argument("--terraform-dir", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    if args.phase == "warm":
        warm_candidate(args.terraform_dir, args.manifest)
    else:
        apply_phase(args.terraform_dir, args.manifest, args.phase)


if __name__ == "__main__":
    main()
