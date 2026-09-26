
from __future__ import annotations
import argparse, json
from pathlib import Path
from .stage_c_duplicate_split_feasibility import load_json
from .stage_c_development_split_freeze import (
    StageCSplitFreezeError,
    freeze_development_split,
    frozen_write_json,
)

def main() -> int:
    p = argparse.ArgumentParser(description="Freeze the exact Stage-C Task-7 recommended development split.")
    p.add_argument("--index", type=Path, required=True)
    p.add_argument("--task6-report", type=Path, required=True)
    p.add_argument("--duplicate-audit", type=Path, required=True)
    p.add_argument("--feasibility", type=Path, required=True)
    p.add_argument("--output-root", type=Path, required=True)
    a = p.parse_args()
    try:
        contract, manifest, quarantine = freeze_development_split(
            index=load_json(a.index),
            task6_report=load_json(a.task6_report),
            audit=load_json(a.duplicate_audit),
            feasibility=load_json(a.feasibility),
        )
        cp=a.output_root/"development-split-contract.json"
        mp=a.output_root/"development-split-manifest.json"
        qp=a.output_root/"development-split-quarantine.json"
        states={
            "contract":frozen_write_json(cp,contract),
            "manifest":frozen_write_json(mp,manifest),
            "quarantine":frozen_write_json(qp,quarantine),
        }
    except (OSError, ValueError, StageCSplitFreezeError) as exc:
        print(json.dumps({"status":"FAIL","error":str(exc)},indent=2))
        return 2

    print(json.dumps({
        "status":"PASS",
        "first_cutoff":contract["cutoffs"]["first"],
        "second_cutoff":contract["cutoffs"]["second"],
        "counts":contract["counts"],
        "chronology_proof":contract["chronology_proof"],
        "artifact_isolation":contract["artifact_isolation"],
        "contract_sha256":contract["contract_sha256"],
        "partition_manifest_sha256":contract["partition_manifest_sha256"],
        "quarantine_manifest_sha256":contract["quarantine_manifest_sha256"],
        "feature_extraction_authorized":False,
        "model_training_authorized":False,
        "final_holdout_touched":False,
        "states":states,
        "outputs":{"contract":str(cp),"manifest":str(mp),"quarantine":str(qp)},
        "next_gate":contract["next_gate"],
    },indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
