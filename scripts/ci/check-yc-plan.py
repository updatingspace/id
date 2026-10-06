"""Reject destructive changes and changes to the serving backend before apply."""

import argparse
import json

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("plan")
parser.add_argument("--snapshot", help="Private blue/green runtime snapshot")
parser.add_argument(
    "--reject-python-deploy",
    action="store_true",
    help="Refuse a new revision of the retired Django backend image",
)
parser.add_argument(
    "--retire-legacy-backend",
    action="store_true",
    help="Permit only removal of the already-deleted Django blue container and its invoker binding",
)
args = parser.parse_args()
with open(args.plan) as stream:
    plan = json.load(stream)
snapshot = None
if args.snapshot:
    with open(args.snapshot) as stream:
        snapshot = json.load(stream)
if args.retire_legacy_backend:
    retained = (snapshot or {}).get("retained_backend_config") or {}
    if not (
        (snapshot or {}).get("rollout_active_slot") == "green"
        and "/updatingspace-id-api" in retained.get("image_url", "")
    ):
        raise SystemExit("Legacy retirement requires a verified live Rust green snapshot")
recreatable = {"terraform_data", "yandex_lockbox_secret_version"}
retired = {
    "yandex_serverless_container.backend",
    "yandex_serverless_container.backend[0]",
    "yandex_serverless_container_iam_binding.gateway_backend_invoker",
    "yandex_serverless_container_iam_binding.gateway_backend_invoker[0]",
} if args.retire_legacy_backend else set()
destructive = [
    change["address"]
    for change in plan.get("resource_changes", [])
    if "delete" in change["change"]["actions"]
    and change["type"] not in recreatable
    and change["address"] not in retired
]
if destructive:
    raise SystemExit(
        "Refusing destructive production changes: " + ", ".join(destructive)
    )
if args.reject_python_deploy:
    python_revisions = [
        change["address"]
        for change in plan.get("resource_changes", [])
        if change["type"] == "yandex_serverless_container"
        and change["change"]["actions"] not in (["no-op"], ["read"])
        and "delete" not in change["change"]["actions"]
        and any(
            "updatingspace-id-backend:" in image.get("url", "")
            for image in (change["change"].get("after") or {}).get("image", [])
        )
    ]
    if python_revisions:
        raise SystemExit(
            "Refusing a new Django backend revision after the Rust Gateway cutover: "
            + ", ".join(python_revisions)
        )
if args.snapshot:
    slot = snapshot.get("rollout_active_slot")
    if slot not in {"blue", "green"}:
        raise SystemExit("Runtime snapshot has no verified serving backend slot")
    serving_address = {
        "blue": "yandex_serverless_container.backend",
        "green": "yandex_serverless_container.backend_green[0]",
    }[slot]
    serving_changes = [
        change["change"]["actions"]
        for change in plan.get("resource_changes", [])
        if change["address"] == serving_address
        and change["change"]["actions"] != ["no-op"]
    ]
    if serving_changes:
        raise SystemExit("Refusing to modify serving backend: " + serving_address)
print("Plan contains no destructive changes to persistent resources.")
