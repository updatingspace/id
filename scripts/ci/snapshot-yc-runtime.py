"""Preserve the deployed runtime environment and secret rotations before apply.

Write only to a private, ignored tfvars file. Never log secret values.
"""

import argparse
import json
import os
import subprocess
from pathlib import Path


def read_json(*command):
    return json.loads(subprocess.check_output(command, text=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform-dir", required=True)
    parser.add_argument("--terraform-bin", default="terraform")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    outputs = read_json(args.terraform_bin, f"-chdir={args.terraform_dir}", "output", "-json")
    # Use the container recorded in this stack's state, not another folder service.
    container_id = outputs["backend_invoke_url"]["value"].split("//", 1)[1].split(".", 1)[0]
    revisions = read_json("yc", "serverless", "container", "revision", "list", "--container-id", container_id, "--format", "json")
    active = [revision for revision in revisions if revision["status"] == "ACTIVE"]
    if len(active) != 1:
        raise RuntimeError("Expected one active backend revision before rollout")
    revision = active[0]
    values = {}
    for secret_id, version_id in {(s["id"], s["version_id"]) for s in revision.get("secrets", [])}:
        payload = read_json("yc", "lockbox", "payload", "get", "--id", secret_id, "--version-id", version_id, "--format", "json")
        entries = {entry["key"]: entry["text_value"] for entry in payload["entries"] if "text_value" in entry}
        for secret in revision["secrets"]:
            if secret["id"] == secret_id and secret["version_id"] == version_id:
                values[secret["environment_variable"]] = entries[secret["key"]]
    result = {
        "existing_api_gateway_id": outputs["api_gateway_id"]["value"],
        "live_service_environment": revision["image"].get("environment", {}),
        "live_secret_entries": values,
    }
    # Resolve deployment-local identifiers into the private tfvars snapshot.
    # The standard network has subnets in all YC availability zones.
    network = read_json("yc", "vpc", "network", "get", "--name", os.environ.get("YC_ID_NETWORK_NAME", "default"), "--format", "json")
    subnet = read_json("yc", "vpc", "subnet", "get", "--name", os.environ.get("YC_ID_CACHE_SUBNET_NAME", "default-ru-central1-a"), "--format", "json")
    if subnet["network_id"] != network["id"]:
        raise RuntimeError("Cache subnet must belong to the selected backend VPC")
    result.update(existing_network_id=network["id"], cache_subnet_id=subnet["id"])
    destination = Path(args.output)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(destination, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(result, stream)
    print(f"Preserved runtime configuration from revision {revision['id']}; secret values were not logged.")


if __name__ == "__main__":
    main()
