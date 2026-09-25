from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from .stage_b_archive_replay import validate_archive_replay_plan
from .stage_b_zenodo8041387 import (
    SOURCE_REFERENCE,
    Zenodo8041387AdapterError,
    adapt_class,
    build_raw_plan,
    common_time_window,
    load_brand_aliases,
    select_pilot,
    sha256_file,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare a safe Stage B pilot from locally extracted Zenodo 8041387 captures."
    )
    parser.add_argument("--phishing-root", type=Path, required=True)
    parser.add_argument("--legitimate-root", type=Path, required=True)
    parser.add_argument("--phishing-csv", type=Path, required=True)
    parser.add_argument("--legitimate-csv", type=Path, required=True)
    parser.add_argument("--brands-csv", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--per-class", type=int, default=40)
    parser.add_argument("--wait-ms", type=int, default=600)
    parser.add_argument("--max-brand-share", type=float, default=0.25)
    parser.add_argument("--license-reference", required=True)
    parser.add_argument("--phishing-id-column")
    parser.add_argument("--phishing-url-column")
    parser.add_argument("--phishing-date-column")
    parser.add_argument("--phishing-brand-column")
    parser.add_argument("--legitimate-id-column")
    parser.add_argument("--legitimate-url-column")
    parser.add_argument("--legitimate-date-column")
    parser.add_argument("--acknowledge-research-use", action="store_true")
    args = parser.parse_args()

    if not args.acknowledge_research_use:
        parser.error(
            "--acknowledge-research-use is required; verify the source record/terms before adaptation"
        )
    if args.per_class < 8:
        parser.error("--per-class must be at least 8 so four research partitions can retain both classes")
    if not (0 < args.max_brand_share <= 1):
        parser.error("--max-brand-share must be in (0, 1]")

    try:
        brands = load_brand_aliases(args.brands_csv)
        phishing, phishing_report = adapt_class(
            args.phishing_root,
            args.phishing_csv,
            label=1,
            brand_aliases=brands,
            id_column=args.phishing_id_column,
            url_column=args.phishing_url_column,
            date_column=args.phishing_date_column,
            brand_column=args.phishing_brand_column,
        )
        legitimate, legitimate_report = adapt_class(
            args.legitimate_root,
            args.legitimate_csv,
            label=0,
            brand_aliases=brands,
            id_column=args.legitimate_id_column,
            url_column=args.legitimate_url_column,
            date_column=args.legitimate_date_column,
        )
        start, end = common_time_window(phishing, legitimate)
        selected_phishing = select_pilot(
            phishing,
            count=args.per_class,
            start=start,
            end=end,
            max_brand_share=args.max_brand_share,
        )
        selected_legitimate = select_pilot(
            legitimate,
            count=args.per_class,
            start=start,
            end=end,
            max_brand_share=args.max_brand_share,
        )
    except Zenodo8041387AdapterError as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    output = args.output_root
    archive_root = output / "archive"
    if output.exists():
        protected = {
            "archive-replay-plan.json",
            "archive-replay-plan.normalized.json",
            "adapter-report.json",
        }
        if any((output / name).exists() for name in protected):
            parser.error("output-root already contains a frozen pilot artifact; choose a new output-root")
    archive_root.mkdir(parents=True, exist_ok=True)

    metadata_hashes = {
        "phishing.csv": sha256_file(args.phishing_csv),
        "not-phishing.csv": sha256_file(args.legitimate_csv),
    }
    if args.brands_csv:
        metadata_hashes["brands.csv"] = sha256_file(args.brands_csv)

    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    raw_plan, build_report = build_raw_plan(
        selected_phishing,
        selected_legitimate,
        output_archive_root=archive_root,
        metadata_hashes=metadata_hashes,
        wait_ms=args.wait_ms,
        license_reference=args.license_reference,
        created_at=created_at,
    )

    raw_path = output / "archive-replay-plan.json"
    normalized_path = output / "archive-replay-plan.normalized.json"
    report_path = output / "adapter-report.json"

    raw_path.write_text(json.dumps(raw_plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    normalized = validate_archive_replay_plan(raw_plan, archive_root)
    normalized_path.write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    report = {
        "status": "PASS",
        "adapter": "zenodo-8041387-pilot-1",
        "source_reference": SOURCE_REFERENCE,
        "shared_time_window": {
            "start": start.isoformat(),
            "end": end.isoformat(),
        },
        "phishing": phishing_report,
        "legitimate": legitimate_report,
        "build": build_report,
        "outputs": {
            "archive_root": str(archive_root),
            "raw_plan": str(raw_path),
            "normalized_plan": str(normalized_path),
        },
        "limitations": [
            "This is a research pilot, not a production-ready or independently sourced dataset.",
            "Raw source URLs are used transiently for domain grouping and are not persisted in the replay plan.",
            "Observed timestamps and target brands remain dependent on the source metadata.",
            "Archived HTML replay cannot reproduce the original live network/server context.",
        ],
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({
        "status": "PASS",
        "selected_per_class": args.per_class,
        "total": args.per_class * 2,
        "normalized_plan": str(normalized_path),
        "archive_root": str(archive_root),
        "report": str(report_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
