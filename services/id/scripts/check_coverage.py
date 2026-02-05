#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass(frozen=True)
class ModuleCoverage:
    line_rate: float
    branch_rate: float


def _normalize_threshold(value: float) -> float:
    if value > 1:
        return value / 100.0
    return value


def _load_coverage(xml_path: str) -> tuple[ModuleCoverage, dict[str, ModuleCoverage]]:
    root = ET.parse(xml_path).getroot()
    total = ModuleCoverage(
        line_rate=float(root.attrib.get("line-rate", "0") or 0.0),
        branch_rate=float(root.attrib.get("branch-rate", "0") or 0.0),
    )
    modules: dict[str, ModuleCoverage] = {}
    for node in root.findall(".//class"):
        filename = str(node.attrib.get("filename") or "").strip()
        if not filename:
            continue
        modules[filename] = ModuleCoverage(
            line_rate=float(node.attrib.get("line-rate", "0") or 0.0),
            branch_rate=float(node.attrib.get("branch-rate", "0") or 0.0),
        )
    return total, modules


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate line/branch coverage thresholds from Cobertura XML."
    )
    parser.add_argument("--xml", default="coverage.xml", help="Path to coverage XML")
    parser.add_argument("--min-line", type=float, required=True)
    parser.add_argument("--min-branch", type=float, required=True)
    parser.add_argument(
        "--critical",
        action="append",
        default=[],
        help="Critical module path in XML (repeatable)",
    )
    parser.add_argument("--critical-min-line", type=float, default=1.0)
    parser.add_argument("--critical-min-branch", type=float, default=1.0)
    args = parser.parse_args()

    min_line = _normalize_threshold(args.min_line)
    min_branch = _normalize_threshold(args.min_branch)
    critical_min_line = _normalize_threshold(args.critical_min_line)
    critical_min_branch = _normalize_threshold(args.critical_min_branch)

    total, modules = _load_coverage(args.xml)
    failures: list[str] = []

    if total.line_rate < min_line:
        failures.append(
            f"TOTAL line-rate {total.line_rate:.4f} < required {min_line:.4f}"
        )
    if total.branch_rate < min_branch:
        failures.append(
            f"TOTAL branch-rate {total.branch_rate:.4f} < required {min_branch:.4f}"
        )

    for module in args.critical:
        cov = modules.get(module)
        if cov is None:
            failures.append(f"Critical module not found in coverage XML: {module}")
            continue
        if cov.line_rate < critical_min_line:
            failures.append(
                f"{module} line-rate {cov.line_rate:.4f} < required {critical_min_line:.4f}"
            )
        if cov.branch_rate < critical_min_branch:
            failures.append(
                f"{module} branch-rate {cov.branch_rate:.4f} < required {critical_min_branch:.4f}"
            )

    print(
        "Coverage summary:"
        f" line={total.line_rate:.4f}"
        f" branch={total.branch_rate:.4f}"
        f" critical_modules={len(args.critical)}"
    )
    if failures:
        print("Coverage gate failed:")
        for item in failures:
            print(f" - {item}")
        return 1

    print("Coverage gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
