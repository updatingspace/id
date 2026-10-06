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
            ]
            with patch.object(snapshot, "read_json", side_effect=responses) as read, patch.object(sys, "argv", ["snapshot", "--terraform-dir", directory, "--output", str(output)]):
                snapshot.main()
            saved = json.loads(output.read_text())
            self.assertEqual(saved["live_secret_entries"], {"EMAIL_HOST_PASSWORD": "test-secret"})
            self.assertEqual(saved["live_service_environment"], {"EMAIL_HOST": "smtp.test"})
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertIn("current", read.call_args_list[2].args)
            self.assertEqual(saved["existing_network_id"], "")
            self.assertEqual(read.call_count, 3)

    def test_snapshot_preserves_live_vpc_without_provisioning_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "live.json"
            responses = [
                {"backend_invoke_url": {"value": "https://container.containers.yandexcloud.net/"}, "api_gateway_id": {"value": "gateway"}},
                [{"id": "active", "status": "ACTIVE", "image": {}, "connectivity": {"network_id": "live-network"}}],
            ]
            with patch.object(snapshot, "read_json", side_effect=responses) as read, patch.object(sys, "argv", ["snapshot", "--terraform-dir", directory, "--output", str(output)]):
                snapshot.main()
            self.assertEqual(json.loads(output.read_text())["existing_network_id"], "live-network")
            self.assertEqual(read.call_count, 2)

    def test_shared_cache_requires_explicit_network_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "live.json"
            responses = [
                {"backend_invoke_url": {"value": "https://container.containers.yandexcloud.net/"}, "api_gateway_id": {"value": "gateway"}},
                [{"id": "active", "status": "ACTIVE", "image": {}}],
                {"id": "network"},
                {"id": "subnet", "network_id": "network"},
            ]
            with patch.object(snapshot, "read_json", side_effect=responses), patch.object(sys, "argv", ["snapshot", "--terraform-dir", directory, "--output", str(output), "--shared-cache"]):
                snapshot.main()
            saved = json.loads(output.read_text())
            self.assertEqual(saved["existing_network_id"], "network")
            self.assertEqual(saved["cache_subnet_id"], "subnet")

    def test_ambiguous_active_revision_does_not_write_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "live.json"
            with patch.object(snapshot, "read_json", side_effect=[{"backend_invoke_url": {"value": "https://container.containers.yandexcloud.net/"}, "api_gateway_id": {"value": "gateway"}}, []]), patch.object(sys, "argv", ["snapshot", "--terraform-dir", directory, "--output", str(output)]):
                with self.assertRaises(RuntimeError):
                    snapshot.main()
            self.assertFalse(output.exists())

    def test_retire_legacy_snapshots_existing_rust_container(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "live.json"
            revision = {"id": "rust-active", "status": "ACTIVE", "image": {"environment": {"BUILD_ID": "rust"}}}
            with patch.object(snapshot, "read_json", return_value=[revision]), \
                 patch.dict(sys.modules, {"yc_rollout": SimpleNamespace(revision_config=lambda _: {"image_url": "rust-image"})}), \
                 patch.object(sys, "argv", ["snapshot", "--terraform-dir", directory, "--output", str(output), "--container-id", "rust-container", "--gateway-id", "gateway", "--retire-legacy"]):
                snapshot.main()
            saved = json.loads(output.read_text())
            self.assertEqual(saved["retained_backend_config"], {"image_url": "rust-image"})
            self.assertEqual(saved["live_service_environment"], {"BUILD_ID": "rust"})
            self.assertEqual(saved["existing_api_gateway_id"], "gateway")

    def test_plan_rejects_persistent_resource_deletion_and_replacement(self):
        for actions in [["delete"], ["delete", "create"]]:
            self.assertNotEqual(self.check_plan("yandex_ydb_database_serverless", actions), 0)

    def test_plan_accepts_additions_updates_and_version_replacement(self):
        for resource, actions in [("yandex_mdb_redis_cluster", ["create"]), ("yandex_serverless_container", ["update"]), ("yandex_lockbox_secret_version", ["delete", "create"]), ("terraform_data", ["delete", "create"])]:
            self.assertEqual(self.check_plan(resource, actions), 0)

    def test_plan_preserves_serving_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            snapshot = Path(directory) / "snapshot.json"
            snapshot.write_text(json.dumps({"rollout_active_slot": "blue"}))
            plan.write_text(json.dumps({"resource_changes": [
                {"address": "yandex_serverless_container.backend", "type": "yandex_serverless_container", "change": {"actions": ["update"]}},
            ]}))
            command = [sys.executable, str(ROOT / "check-yc-plan.py"), str(plan), "--snapshot", str(snapshot)]
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            plan.write_text(json.dumps({"resource_changes": [
                {"address": "yandex_serverless_container.backend_green[0]", "type": "yandex_serverless_container", "change": {"actions": ["update"]}},
            ]}))
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_rust_cutover_refuses_new_python_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            command = [sys.executable, str(ROOT / "check-yc-plan.py"), str(plan), "--reject-python-deploy"]
            for actions, image, allowed in [
                (["no-op"], "updatingspace-id-backend:old", True),
                (["update"], "updatingspace-id-backend:new", False),
                (["create"], "updatingspace-id-backend:new", False),
                (["update"], "updatingspace-id-api:new", True),
            ]:
                plan.write_text(json.dumps({"resource_changes": [{
                    "address": "yandex_serverless_container.backend_green[0]",
                    "type": "yandex_serverless_container",
                    "change": {"actions": actions, "after": {"image": [{"url": "cr.yandex/registry/" + image}]}},
                }]}))
                result = subprocess.run(command, capture_output=True)
                self.assertEqual(result.returncode == 0, allowed, result.stderr.decode())

    def test_legacy_retirement_allows_only_deleted_blue_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            snapshot_file = Path(directory) / "snapshot.json"
            snapshot_file.write_text(json.dumps({
                "rollout_active_slot": "green",
                "retained_backend_config": {"image_url": "cr.yandex/registry/updatingspace-id-api@sha256:" + "a" * 64},
            }))
            command = [sys.executable, str(ROOT / "check-yc-plan.py"), str(plan), "--snapshot", str(snapshot_file), "--retire-legacy-backend"]
            for address, allowed in [
                ("yandex_serverless_container.backend[0]", True),
                ("yandex_serverless_container_iam_binding.gateway_backend_invoker[0]", True),
                ("yandex_serverless_container.backend_green[0]", False),
                ("yandex_ydb_database_serverless.id", False),
            ]:
                plan.write_text(json.dumps({"resource_changes": [{
                    "address": address,
                    "type": address.split(".", 1)[0],
                    "change": {"actions": ["delete"]},
                }]}))
                result = subprocess.run(command, capture_output=True)
                self.assertEqual(result.returncode == 0, allowed, result.stderr.decode())

    def check_plan(self, resource, actions):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.json"
            plan.write_text(json.dumps({"resource_changes": [{"address": resource + ".test", "type": resource, "change": {"actions": actions}}]}))
            return subprocess.run([sys.executable, str(ROOT / "check-yc-plan.py"), str(plan)], capture_output=True).returncode


if __name__ == "__main__":
    unittest.main()
