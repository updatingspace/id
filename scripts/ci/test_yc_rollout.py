"""Deployment regression checks that never access cloud credentials."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location("snapshot", ROOT / "snapshot-yc-runtime.py")
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class RolloutTests(unittest.TestCase):
    def test_snapshot_preserves_active_revision_values_in_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "live.auto.tfvars.json"
            responses = [
                {"backend_invoke_url": {"value": "https://container.containers.yandexcloud.net/"}, "api_gateway_id": {"value": "gateway"}},
                [{"id": "active", "status": "ACTIVE", "image": {"environment": {"EMAIL_HOST": "smtp.test"}},
                  "secrets": [{"id": "lockbox", "version_id": "current", "key": "smtp", "environment_variable": "EMAIL_HOST_PASSWORD"}]}],
                {"entries": [{"key": "smtp", "text_value": "test-secret"}, {"key": "unused", "text_value": "unused-secret"}]},
                {"id": "network"},
                {"id": "subnet", "network_id": "network"},
            ]
            with patch.object(snapshot, "read_json", side_effect=responses) as read, patch.object(sys, "argv", ["snapshot", "--terraform-dir", directory, "--output", str(output)]):
                snapshot.main()
            saved = json.loads(output.read_text())
            self.assertEqual(saved["live_secret_entries"], {"EMAIL_HOST_PASSWORD": "test-secret"})
            self.assertEqual(saved["live_service_environment"], {"EMAIL_HOST": "smtp.test"})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn("current", read.call_args_list[2].args)
            self.assertEqual(saved["existing_network_id"], "network")

    def test_ambiguous_active_revision_does_not_write_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "live.json"
            with patch.object(snapshot, "read_json", side_effect=[{"backend_invoke_url": {"value": "https://container.containers.yandexcloud.net/"}}, []]), patch.object(sys, "argv", ["snapshot", "--terraform-dir", directory, "--output", str(output)]):
                with self.assertRaises(RuntimeError):
                    snapshot.main()
            self.assertFalse(output.exists())

    def test_plan_rejects_persistent_resource_deletion_and_replacement(self):
        for actions in [["delete"], ["delete", "create"]]:
            self.assertNotEqual(self.check_plan("yandex_ydb_database_serverless", actions), 0)

    def test_plan_accepts_additions_updates_and_version_replacement(self):
        for resource, actions in [("yandex_mdb_redis_cluster", ["create"]), ("yandex_serverless_container", ["update"]), ("yandex_lockbox_secret_version", ["delete", "create"]), ("terraform_data", ["delete", "create"])]:
            self.assertEqual(self.check_plan(resource, actions), 0)

    def check_plan(self, resource, actions):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            plan.write_text(json.dumps({"resource_changes": [{"address": resource + ".test", "type": resource, "change": {"actions": actions}}]}))
            return subprocess.run([sys.executable, str(ROOT / "check-yc-plan.py"), str(plan)], capture_output=True).returncode


if __name__ == "__main__":
    unittest.main()
