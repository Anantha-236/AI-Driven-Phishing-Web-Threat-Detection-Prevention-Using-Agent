from __future__ import annotations
import argparse, json
from pathlib import Path
from .stage_c_dataset_qualification import (
    StageCDatasetQualificationError,
    build_acquisition_plan,
    load_json,
)

def main() -> int:
    parser = argparse.ArgumentParser(description="Qualify Stage-C dataset candidates.")
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_acquisition_plan(load_json(args.catalog))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output.exists() and args.output.read_text(encoding="utf-8") != rendered:
            raise StageCDatasetQualificationError(
                f"refusing to replace non-identical frozen acquisition plan: {args.output}"
            )
        if not args.output.exists():
            args.output.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, StageCDatasetQualificationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
