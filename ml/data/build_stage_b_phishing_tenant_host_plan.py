from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_phishing_tenant_host import (
    TenantHostExperimentError,
    build_phishing_tenant_host_plan,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a non-destructive exact-host phishing grouping experiment."
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--phishing-csv", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    try:
        source = json.loads(args.plan.read_text(encoding="utf-8"))
        plan, report = build_phishing_tenant_host_plan(source, args.phishing_csv)
    except (OSError, json.JSONDecodeError, TenantHostExperimentError, ValueError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": "PASS",
        "phishing_samples": report["phishing_samples"],
        "changed_domain_groups": report["changed_domain_groups"],
        "unique_domain_groups_before": report["unique_domain_groups_before"],
        "unique_domain_groups_after": report["unique_domain_groups_after"],
        "largest_groups_before": report["largest_groups_before"][:10],
        "largest_groups_after": report["largest_groups_after"][:10],
        "output": str(args.output),
        "report": str(args.report),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
