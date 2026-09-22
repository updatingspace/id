"""Terraform compatibility adapter for an existing, non-importable gateway."""

import os
import subprocess
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory(prefix="id-gateway-") as directory:
    spec = Path(directory) / "gateway.yaml"
    spec.write_text(os.environ["YC_GATEWAY_SPEC"])
    subprocess.run(
        ["yc", "serverless", "api-gateway", "update", "--id", os.environ["YC_GATEWAY_ID"], "--spec", str(spec)],
        check=True,
    )
