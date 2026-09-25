from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_b_zenodo8041387 import adapt_class, discover_html, read_csv


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect real Zenodo 8041387 pilot inputs and metadata joins.")
    parser.add_argument("--phishing-root", type=Path, required=True)
    parser.add_argument("--legitimate-root", type=Path, required=True)
    parser.add_argument("--phishing-csv", type=Path, required=True)
    parser.add_argument("--legitimate-csv", type=Path, required=True)
    args = parser.parse_args()

    p_headers, p_rows = read_csv(args.phishing_csv)
    l_headers, l_rows = read_csv(args.legitimate_csv)
    p_html = discover_html(args.phishing_root)
    l_html = discover_html(args.legitimate_root)
    output = {
        "status": "PASS",
        "phishing": {"csv_rows": len(p_rows), "csv_columns": p_headers, "archive_record_ids_detected": len(p_html), "archive_record_id_examples": [str(v) for v in sorted(p_html, key=str)[:20]]},
        "legitimate": {"csv_rows": len(l_rows), "csv_columns": l_headers, "archive_record_ids_detected": len(l_html), "archive_record_id_examples": [str(v) for v in sorted(l_html, key=str)[:20]]},
    }
    for name, root, csv_path, label in (("phishing", args.phishing_root, args.phishing_csv, 1), ("legitimate", args.legitimate_root, args.legitimate_csv, 0)):
        try:
            records, report = adapt_class(root, csv_path, label=label, brand_aliases={})
            output[name]["usable_records"] = len(records)
            output[name]["join"] = report
        except Exception as exc:
            output[name]["join_error"] = f"{type(exc).__name__}: {exc}"
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
