from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_dataset_registry import (
    StageCDatasetRegistryError,
    build_consumed_stage_b_guard,
)
from .stage_c_protocol import load_json


def _frozen_write(path: Path, value) -> str:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise StageCDatasetRegistryError(
                f"refusing to replace non-identical consumed-test guard: {path}"
            )
        return "EXISTING_MATCH"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    return "CREATED"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the Stage-C contamination guard from the consumed Stage-B final test."
    )
    parser.add_argument("--stage-b-features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        guard = build_consumed_stage_b_guard(load_json(args.stage_b_features))
        state = _frozen_write(args.output, guard)
    except (OSError, ValueError, StageCDatasetRegistryError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2
    print(json.dumps({
        "status": "PASS",
        "state": state,
        "sample_count": guard["sample_count"],
        "class_counts": guard["class_counts"],
        "test_partition_sha256": guard["test_partition_sha256"],
        "identity_set_sha256": guard["identity_set_sha256"],
        "output": str(args.output),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
