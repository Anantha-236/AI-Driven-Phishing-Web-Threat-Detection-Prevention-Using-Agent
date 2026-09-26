
from __future__ import annotations
import argparse, json
from pathlib import Path
from .stage_c_local_download_seal import StageCLocalSealError, load_json, seal_public_download

def frozen_write(path: Path, value: dict) -> str:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing != value:
            raise StageCLocalSealError(f"refusing to replace non-identical frozen local seal: {path}")
        return "EXISTING_MATCH"
    path.write_text(rendered, encoding="utf-8")
    return "CREATED"

def main() -> int:
    parser = argparse.ArgumentParser(description="Seal the Stage-C public development download locally.")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = seal_public_download(archive_path=args.archive, spec=load_json(args.spec))
        state = frozen_write(args.output, result)
    except (OSError, ValueError, StageCLocalSealError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2
    print(json.dumps({
        "status": "PASS",
        "verification_mode": result["verification_mode"],
        "archive_sha256": result["archive"]["sha256"],
        "archive_size_bytes": result["archive"]["size_bytes"],
        "members": result["archive"]["member_count"],
        "member_set_sha256": result["member_set_sha256"],
        "model_training_authorized": False,
        "extraction_authorized": False,
        "final_holdout_touched": False,
        "state": state,
        "output": str(args.output),
        "next_gate": result["next_gate"],
    }, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
