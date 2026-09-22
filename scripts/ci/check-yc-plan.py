"""Reject deletion/replacement of persistent production resources before apply."""

import json
import sys

plan = json.load(open(sys.argv[1]))
recreatable = {"terraform_data", "yandex_lockbox_secret_version"}
destructive = [
    change["address"]
    for change in plan.get("resource_changes", [])
    if "delete" in change["change"]["actions"] and change["type"] not in recreatable
]
if destructive:
    raise SystemExit("Refusing destructive production changes: " + ", ".join(destructive))
print("Plan contains no destructive changes to persistent resources.")
