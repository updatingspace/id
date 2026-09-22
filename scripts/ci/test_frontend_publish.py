"""Exercise release ordering/retention with a local fake S3, without credentials."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("deploy-frontend-object-storage.sh")


class FrontendPublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist with spaces"
        self.bucket = self.root / "bucket"
        (self.dist / "assets").mkdir(parents=True)
        (self.bucket / "assets").mkdir(parents=True)
        (self.bucket / "assets/previous-12345678.js").write_text("previous release")
        (self.bucket / "index.html").write_text("previous index")
        (self.dist / "index.html").write_text("new index")
        (self.dist / "assets/index-12345678.js").write_text("new js")
        (self.dist / "assets/index-CjO8uOY-.css").write_text("new css")
        (self.dist / "favicon.svg").write_text("icon")
        self.log = self.root / "uploads.jsonl"
        fake = self.root / "aws"
        fake.write_text("""#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
a = sys.argv[1:]
assert a[2:4] == ['s3', 'cp'], a
source, destination = a[4:6]
key = destination.split('/', 3)[3]
with open(os.environ['UPLOAD_LOG'], 'a') as log:
    log.write(json.dumps({'key': key, 'args': a}) + '\\n')
if key == os.environ.get('FAIL_KEY'):
    sys.exit(1)
target = pathlib.Path(os.environ['FAKE_BUCKET']) / key
target.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(source, target)
""")
        fake.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
            "YC_BUCKET_NAME": "test-bucket",
            "FRONTEND_DIST_DIR": str(self.dist) + "/",
            "FAKE_BUCKET": str(self.bucket),
            "UPLOAD_LOG": str(self.log),
        }

    def publish(self, **env):
        return subprocess.run(["bash", str(SCRIPT)], env={**self.env, **env}, capture_output=True, text=True)

    def test_index_is_last_assets_are_immutable_and_previous_release_is_retained(self):
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        uploads = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(uploads[-1]["key"], "index.html")
        self.assertEqual(len(uploads), 4)
        for upload in uploads:
            args = upload["args"]
            ttl = args[args.index("--cache-control") + 1]
            if upload["key"].startswith("assets/"):
                self.assertEqual(ttl, "public,max-age=31536000,immutable")
            elif upload["key"] == "index.html":
                self.assertEqual(ttl, "no-cache")
            else:
                self.assertEqual(ttl, "public,max-age=300")
        self.assertTrue((self.bucket / "assets/previous-12345678.js").exists())
        self.assertEqual((self.bucket / "index.html").read_text(), "new index")

    def test_failed_dependency_upload_does_not_publish_index(self):
        result = self.publish(FAIL_KEY="assets/index-12345678.js")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.bucket / "index.html").read_text(), "previous index")
        self.assertNotIn('"key": "index.html"', self.log.read_text())

    def test_missing_index_fails_before_upload(self):
        (self.dist / "index.html").unlink()
        self.assertNotEqual(self.publish().returncode, 0)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
