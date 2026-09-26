from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage_c_remote_inventory import (
    DEFAULT_API_BASE,
    StageCRemoteInventoryError,
    fetch_public_dataset_inventory,
    freeze_remote_inventories,
    load_optional_token,
)


def _load(path: Path) -> dict:
    if not path.is_file():
        raise StageCRemoteInventoryError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCRemoteInventoryError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCRemoteInventoryError(f"JSON root must be object: {path}")
    return value


def _write_once(path: Path, value: dict) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if existing != rendered:
            raise StageCRemoteInventoryError(
                f"refusing to replace non-identical frozen artifact: {path}"
            )
        return
    path.write_text(rendered, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify pinned Stage-C Mendeley file inventories and freeze manifests."
    )
    parser.add_argument("--acquisition-plan", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument("--token-env", default="MENDELEY_DATA_TOKEN")
    args = parser.parse_args()

    try:
        plan = _load(args.acquisition_plan)
        token = load_optional_token(args.token_env)

        def fetch(doi: str):
            return fetch_public_dataset_inventory(
                doi=doi,
                api_base=args.api_base,
                token=token,
            )

        result = freeze_remote_inventories(
            acquisition_plan=plan,
            fetch_inventory=fetch,
        )
        development = result.pop("_development_manifest")
        final = result.pop("_final_manifest")

        _write_once(
            args.output_root / "development-download-manifest.json",
            development,
        )
        _write_once(
            args.output_root / "final-holdout-download-manifest.json",
            final,
        )

        result["outputs"] = {
            "development_manifest": str(
                args.output_root / "development-download-manifest.json"
            ),
            "final_holdout_manifest": str(
                args.output_root / "final-holdout-download-manifest.json"
            ),
            "report": str(args.output_root / "remote-inventory-report.json"),
        }
        _write_once(
            args.output_root / "remote-inventory-report.json",
            result,
        )
    except (OSError, ValueError, StageCRemoteInventoryError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
