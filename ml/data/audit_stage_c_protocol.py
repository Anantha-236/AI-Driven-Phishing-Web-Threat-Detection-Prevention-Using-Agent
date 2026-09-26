from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_protocol import (
    StageCProtocolError,
    build_protocol_readiness,
    load_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the Stage C low-FPR experiment protocol."
    )
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--feature-semantics", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        readiness = build_protocol_readiness(
            load_json(args.contract),
            load_json(args.feature_semantics),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(readiness, indent=2, sort_keys=True) + "\n"
        if args.output.exists():
            existing = args.output.read_text(encoding="utf-8")
            if existing != rendered:
                raise StageCProtocolError(
                    f"refusing to replace non-identical readiness artifact: {args.output}"
                )
        else:
            args.output.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, StageCProtocolError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps(readiness, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
