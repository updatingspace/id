"""Release safety checks with synthetic state; no cloud credentials or HTTP traffic."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import yc_rollout as rollout

ROUTES = (
    "/api/v1/{proxy+}",
    "/oauth/{proxy+}",
    "/.well-known/{proxy+}",
    "/health",
    "/healthz",
    "/readyz",
)


def gateway(container):
    return yaml.safe_dump(
        {
            "paths": {
                path: {
                    "get": {
                        "x-yc-apigateway-integration": {
                            "type": "serverless_containers",
                            "container_id": container,
                        }
                    }
                }
                for path in ROUTES
            }
        }
    )


def revision(container="blue-id", identity="revision"):
    return {
        "id": identity,
        "status": "ACTIVE",
        "container_id": container,
        "created_at": "2020-01-01T00:00:00Z",
        "runtime": {"http": {}},
        "image": {
            "image_url": "cr.yandex/registry/backend:release",
            "environment": {"SMTP": "preserve"},
        },
        "resources": {"memory": "1073741824", "cores": "1", "core_fraction": "100"},
        "concurrency": "8",
        "execution_timeout": "60s",
        "service_account_id": "runtime",
        "provision_policy": {"min_instances": "1"},
        "log_options": {"log_group_id": "logs"},
        "metadata_options": {"gce_http_endpoint": "ENABLED"},
        "secrets": [
            {
                "id": "lockbox",
                "version_id": "rotated",
                "key": "smtp",
                "environment_variable": "SMTP_PASSWORD",
            }
        ],
    }


def manifest(original="blue"):
    target = "green" if original == "blue" else "blue"
    return {
        "original_slot": original,
        "target_slot": target,
        "original_container_id": original + "-id",
        "gateway_id": "gateway",
        "gateway_spec_before": gateway(original + "-id"),
        "release_tag": "release",
        "verified_revision_id": "verified",
        "preparation_started": True,
        "promotion_attempted": False,
    }


def change(address, actions=None, before=None, after=None):
    return {
        "address": address,
        "type": address.split(".")[0],
        "change": {"actions": actions or ["update"], "before": before, "after": after},
    }


def plan(*changes):
    return {"resource_changes": list(changes)}


class BlueGreenTests(unittest.TestCase):
    def test_snapshot_uses_live_gateway_even_when_output_slot_is_stale(self):
        for original in ("blue", "green"):
            with self.subTest(original=original):
                outputs = {
                    "api_gateway_id": {"value": "gateway"},
                    "backend_invoke_url": {
                        "value": "https://blue-id.containers.yandexcloud.net/"
                    },
                    "backend_slots": {
                        "value": {
                            "active_slot": "blue",
                            "ids": {"blue": "blue-id", "green": "green-id"},
                        }
                    },
                }
                with (
                    patch.object(
                        rollout,
                        "read_json",
                        return_value={"openapi_spec": gateway(original + "-id")},
                    ),
                    patch.object(rollout, "active_revision", return_value=revision()),
                ):
                    identity, config, saved = rollout.rollout_snapshot(
                        outputs, "release"
                    )
                self.assertEqual(identity, original + "-id")
                self.assertEqual(config["rollout_active_slot"], original)
                self.assertNotEqual(config["rollout_target_slot"], original)
                self.assertEqual(
                    config["retained_backend_config"]["secrets"][0]["version_id"],
                    "rotated",
                )
                self.assertEqual(
                    config["retained_backend_config"]["metadata_options"][
                        "gce_http_endpoint"
                    ],
                    1,
                )
                self.assertFalse(saved["promotion_attempted"])

    def test_legacy_stack_can_be_snapshotted_without_green_output(self):
        outputs = {
            "api_gateway_id": {"value": "gateway"},
            "backend_invoke_url": {
                "value": "https://blue-id.containers.yandexcloud.net/"
            },
        }
        with (
            patch.object(
                rollout, "read_json", return_value={"openapi_spec": gateway("blue-id")}
            ),
            patch.object(rollout, "active_revision", return_value=revision()),
        ):
            _, config, _ = rollout.rollout_snapshot(outputs, "release")
        self.assertEqual(config["rollout_target_slot"], "green")

    def test_unknown_or_mixed_gateway_targets_are_rejected(self):
        outputs = {
            "api_gateway_id": {"value": "gateway"},
            "backend_invoke_url": {
                "value": "https://blue-id.containers.yandexcloud.net/"
            },
        }
        with (
            patch.object(
                rollout,
                "read_json",
                return_value={"openapi_spec": gateway("unmanaged")},
            ),
            self.assertRaises(RuntimeError),
        ):
            rollout.rollout_snapshot(outputs, "release")
        with self.assertRaises(RuntimeError):
            rollout.gateway_backend(
                gateway("blue-id").replace("blue-id", "other-id", 1)
            )

    def test_unsupported_runtime_configuration_is_not_silently_dropped(self):
        for field, value in [
            ("scaling_policy", {"zone_instances_limit": 2}),
            ("mounts", [{"name": "data"}]),
            ("runtime", {"task": {}}),
        ]:
            item = revision()
            item[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                rollout.revision_config(item)
        item = revision()
        item["image"]["command"] = ["custom"]
        with self.assertRaises(RuntimeError):
            rollout.revision_config(item)

    def test_prepare_rejects_serving_container_and_gateway_changes_in_both_directions(
        self,
    ):
        for original in ("blue", "green"):
            saved = manifest(original)
            rollout.validate_plan(
                plan(change(rollout.SLOTS[saved["target_slot"]])), saved, "prepare"
            )
            for address in (rollout.SLOTS[original], *rollout.GATEWAYS):
                with self.subTest(address=address), self.assertRaises(RuntimeError):
                    rollout.validate_plan(plan(change(address)), saved, "prepare")

    def test_promotion_and_rollback_only_allow_gateway_updates(self):
        for phase in ("promote", "rollback"):
            rollout.validate_plan(
                plan(
                    change(
                        "terraform_data.existing_gateway_spec[0]", ["delete", "create"]
                    )
                ),
                manifest(),
                phase,
            )
            for address in (
                *rollout.SLOTS.values(),
                "yandex_lockbox_secret_version.runtime",
                "yandex_ydb_table.cache",
            ):
                with (
                    self.subTest(phase=phase, address=address),
                    self.assertRaises(RuntimeError),
                ):
                    rollout.validate_plan(plan(change(address)), manifest(), phase)

    def test_every_phase_rejects_persistent_resource_deletion(self):
        for phase in ("prepare", "promote", "retire", "rollback", "abort"):
            with self.subTest(phase=phase), self.assertRaises(RuntimeError):
                rollout.validate_plan(
                    plan(
                        change(
                            "yandex_ydb_database_serverless.id", ["delete", "create"]
                        )
                    ),
                    manifest(),
                    phase,
                )

    def test_cleanup_only_changes_inactive_capacity_not_image_or_environment(self):
        before = {
            "image": [{"url": "old-image", "environment": {"SMTP": "value"}}],
            "provision_policy": [{"min_instances": 1}],
        }
        after = copy.deepcopy(before)
        after["provision_policy"] = []
        for phase, slot in (("retire", "blue"), ("abort", "green")):
            saved = manifest()
            address = rollout.SLOTS[slot]
            rollout.validate_plan(
                plan(change(address, before=before, after=after)), saved, phase
            )
            for key, value in (
                ("url", "different-image"),
                ("environment", {"SMTP": "changed"}),
            ):
                bad = copy.deepcopy(after)
                bad["image"][0][key] = value
                with self.assertRaises(RuntimeError):
                    rollout.validate_plan(
                        plan(change(address, before=before, after=bad)), saved, phase
                    )
            with self.assertRaises(RuntimeError):
                rollout.validate_plan(
                    plan(change(address, ["create"], after=after)), saved, phase
                )

    def test_private_files_fix_preexisting_permissive_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.touch(mode=0o644)
            rollout.write_private(path, {"private": "snapshot"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_iam_token_endpoint_is_validated_before_any_request(self):
        saved = manifest()
        for url in (
            "https://evil.test/",
            "https://green-id.containers.yandexcloud.net@evil.test/",
            "http://green-id.containers.yandexcloud.net/",
            "https://green-id.containers.yandexcloud.net/?token=x",
        ):
            outputs = {
                "backend_slots": {
                    "value": {
                        "enabled": True,
                        "target_slot": "green",
                        "ids": {"green": "green-id"},
                        "urls": {"green": url},
                    }
                }
            }
            with (
                patch.object(rollout, "outputs", return_value=outputs),
                patch.object(rollout, "active_revision") as read,
                self.assertRaises(RuntimeError),
            ):
                rollout.target_identity(Path("terraform"), saved)
            read.assert_not_called()

    def test_promotion_rechecks_exact_verified_revision_and_gateway(self):
        with (
            patch.object(
                rollout,
                "target_identity",
                return_value=(
                    "green-id",
                    "https://green-id.containers.yandexcloud.net/",
                ),
            ),
            patch.object(
                rollout, "active_revision", return_value=revision(identity="different")
            ),
            self.assertRaises(RuntimeError),
        ):
            rollout.verify_candidate(Path("terraform"), manifest())
        with (
            patch.object(rollout, "target_identity", return_value=("green-id", "url")),
            patch.object(
                rollout, "active_revision", return_value=revision(identity="verified")
            ),
            patch.object(
                rollout, "read_json", return_value={"openapi_spec": gateway("other")}
            ),
            self.assertRaises(RuntimeError),
        ):
            rollout.verify_candidate(Path("terraform"), manifest())

    def test_readiness_failure_never_records_verified_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            rollout.write_private(path, manifest())
            with (
                patch.object(
                    rollout,
                    "target_identity",
                    return_value=(
                        "green-id",
                        "https://green-id.containers.yandexcloud.net/",
                    ),
                ),
                patch.object(
                    rollout,
                    "active_revision",
                    return_value=revision(identity="candidate"),
                ),
                patch.object(
                    rollout.subprocess, "check_output", return_value="private-token"
                ),
                patch.object(rollout.time, "monotonic", side_effect=[0, 301]),
                self.assertRaises(RuntimeError),
            ):
                rollout.warm_candidate(Path("terraform"), path)
            self.assertEqual(
                json.loads(path.read_text())["verified_revision_id"], "verified"
            )

    def test_prepare_rejection_never_applies_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            rollout.write_private(path, manifest())
            with (
                patch.object(rollout, "run_terraform") as run,
                patch.object(
                    rollout,
                    "read_json",
                    return_value=plan(change(rollout.SLOTS["blue"])),
                ),
                self.assertRaises(RuntimeError),
            ):
                rollout.apply_phase(Path("terraform"), path, "prepare")
            self.assertEqual(run.call_count, 1)
            self.assertIn("plan", run.call_args.args[0])

    def test_only_added_sensitive_marks_can_bypass_runtime_guard(self):
        value = {"image": [{"environment": {"SMTP": "private"}}], "memory": 1024}
        item = change(rollout.SLOTS["blue"], before=value, after=copy.deepcopy(value))
        item["change"].update(
            before_sensitive={"image": [{"environment": {}}]},
            after_sensitive={"image": [{"environment": True}]},
            after_unknown={},
        )
        rollout.validate_plan(plan(item), manifest(), "prepare")
        for modification in ("value", "unknown", "remove-mark", "same-marks"):
            bad = copy.deepcopy(item)
            if modification == "value":
                bad["change"]["after"]["memory"] = 2048
            elif modification == "unknown":
                bad["change"]["after_unknown"] = {"image": [{"environment": True}]}
            elif modification == "remove-mark":
                bad["change"]["before_sensitive"], bad["change"]["after_sensitive"] = (
                    bad["change"]["after_sensitive"],
                    bad["change"]["before_sensitive"],
                )
            else:
                bad["change"]["after_sensitive"] = bad["change"]["before_sensitive"]
            with (
                self.subTest(modification=modification),
                self.assertRaises(RuntimeError),
            ):
                rollout.validate_plan(plan(bad), manifest(), "prepare")

    def test_capacity_cleanup_cannot_increase_prepared_instances(self):
        value = {"image": [{"url": "same"}], "provision_policy": [{"min_instances": 1}]}
        with self.assertRaises(RuntimeError):
            rollout.validate_plan(
                plan(change(rollout.SLOTS["blue"], before=value, after=value)),
                manifest(),
                "retire",
            )

    def test_rollback_before_promotion_does_not_read_or_mutate_cloud(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            rollout.write_private(path, manifest())
            with (
                patch.object(rollout, "read_json") as read,
                patch.object(rollout, "run_terraform") as run,
            ):
                rollout.apply_phase(Path("terraform"), path, "rollback")
            read.assert_not_called()
            run.assert_not_called()

    def test_candidate_is_verified_only_after_database_and_cache_checks(self):
        requests = []

        class Connection:
            def __init__(self, host, timeout):
                self.path = None

            def request(self, method, path, headers):
                requests.append((method, path, headers))
                self.path = path

            def getresponse(self):
                class Response:
                    status = 200

                    def read(inner, limit):
                        return json.dumps(
                            {"status": "ready"}
                            if self.path == "/readyz"
                            else {"form_token": "synthetic"}
                        ).encode()

                return Response()

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            saved = manifest()
            saved.pop("verified_revision_id")
            rollout.write_private(path, saved)
            with (
                patch.object(
                    rollout,
                    "target_identity",
                    return_value=(
                        "green-id",
                        "https://green-id.containers.yandexcloud.net/",
                    ),
                ),
                patch.object(
                    rollout,
                    "active_revision",
                    return_value=revision(identity="candidate"),
                ),
                patch.object(
                    rollout.subprocess, "check_output", return_value="private-token"
                ),
                patch.object(rollout.http.client, "HTTPSConnection", Connection),
                patch.object(rollout.time, "sleep"),
            ):
                rollout.warm_candidate(Path("terraform"), path)
            self.assertEqual(
                json.loads(path.read_text())["verified_revision_id"], "candidate"
            )
            self.assertEqual(len(requests), 16)
            self.assertEqual(
                {path for _, path, _ in requests},
                {"/readyz", "/api/v1/auth/form_token?purpose=login"},
            )
            self.assertTrue(
                all(
                    headers["X-Forwarded-Proto"] == "https"
                    for _, _, headers in requests
                )
            )

    def test_workflow_only_promotes_after_migrations_build_and_warm_checks(self):
        # BaseLoader avoids treating the GitHub 'on' key as YAML 1.1 boolean.
        document = yaml.load(
            (
                Path(__file__).parents[2] / ".github/workflows/deploy-yandex-cloud.yml"
            ).read_text(),
            Loader=yaml.BaseLoader,
        )
        steps = document["jobs"]["release"]["steps"]
        commands = [step.get("run", "") for step in steps]

        def at(fragment):
            return next(i for i, command in enumerate(commands) if fragment in command)

        self.assertLess(at("manage.py migrate_ydb"), at("yc_rollout.py warm"))
        self.assertLess(at("pnpm build"), at("yc_rollout.py warm"))
        self.assertLess(at("yc_rollout.py warm"), at("yc_rollout.py promote"))
        self.assertLess(
            at("yc_rollout.py promote"), at("deploy-frontend-object-storage.sh")
        )
        self.assertLess(at("smoke-yc-gateway.sh"), at("yc_rollout.py retire"))
        for phase in ("rollback", "abort"):
            self.assertIn(
                "steps.smoke.outcome != 'success'",
                steps[at("yc_rollout.py " + phase)]["if"],
            )


if __name__ == "__main__":
    unittest.main()
