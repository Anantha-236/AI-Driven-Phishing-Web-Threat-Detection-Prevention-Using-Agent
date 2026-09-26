"""Stage C Task 3: qualify candidate datasets before acquisition.

This task freezes a research-data acquisition plan only. It does not download
candidate data, materialize features, train models, or unlock the final holdout.
"""
from __future__ import annotations

from datetime import date
import json
from pathlib import Path
from typing import Any, Mapping

CATALOG_SCHEMA = "stage-c-dataset-candidate-catalog-1"
PLAN_SCHEMA = "stage-c-dataset-acquisition-plan-1"

class StageCDatasetQualificationError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCDatasetQualificationError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCDatasetQualificationError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageCDatasetQualificationError("JSON root must be an object")
    return value


def _parse_date(value: Any) -> date:
    if not isinstance(value, str) or not value:
        raise StageCDatasetQualificationError("date value is required")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise StageCDatasetQualificationError(f"invalid date: {value}") from exc


def _period_bounds(candidate: Mapping[str, Any]) -> tuple[date | None, date | None]:
    period = candidate.get("collection_period")
    if not isinstance(period, Mapping):
        return None, None
    starts = [
        _parse_date(v)
        for key, v in period.items()
        if key.endswith("start") or key == "start"
    ]
    ends = [
        _parse_date(v)
        for key, v in period.items()
        if key.endswith("end") or key == "end"
    ]
    return (min(starts) if starts else None, max(ends) if ends else None)


def validate_catalog(catalog: Mapping[str, Any]) -> dict[str, Any]:
    if catalog.get("schema_version") != CATALOG_SCHEMA:
        raise StageCDatasetQualificationError("unsupported Stage-C candidate catalog")
    if catalog.get("stage") != "C":
        raise StageCDatasetQualificationError("catalog must declare Stage C")
    if catalog.get("research_only") is not True:
        raise StageCDatasetQualificationError("catalog must remain research-only")
    if catalog.get("deployment_authorized") is not False:
        raise StageCDatasetQualificationError("catalog cannot authorize deployment")

    candidates = catalog.get("candidates")
    if not isinstance(candidates, list) or len(candidates) < 2:
        raise StageCDatasetQualificationError("at least two candidates are required")
    seen = set()
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            raise StageCDatasetQualificationError("candidate must be an object")
        cid = candidate.get("candidate_id")
        if not isinstance(cid, str) or not cid or cid in seen:
            raise StageCDatasetQualificationError("candidate_id missing or duplicated")
        seen.add(cid)
        for key in ("source_id", "title", "landing_page", "license"):
            if not isinstance(candidate.get(key), str) or not candidate[key]:
                raise StageCDatasetQualificationError(f"{cid} missing {key}")
        roles = candidate.get("role_eligibility")
        if not isinstance(roles, list) or not roles:
            raise StageCDatasetQualificationError(f"{cid} role_eligibility missing")
        if not isinstance(candidate.get("capture_format"), list):
            raise StageCDatasetQualificationError(f"{cid} capture_format missing")

    pair = catalog.get("recommended_pair")
    if not isinstance(pair, Mapping):
        raise StageCDatasetQualificationError("recommended_pair is required")
    if pair.get("development_candidate_id") not in seen:
        raise StageCDatasetQualificationError("unknown recommended development candidate")
    if pair.get("final_holdout_candidate_id") not in seen:
        raise StageCDatasetQualificationError("unknown recommended final candidate")
    if pair.get("development_candidate_id") == pair.get("final_holdout_candidate_id"):
        raise StageCDatasetQualificationError("development and final candidates must differ")
    return json.loads(json.dumps(catalog))


def build_acquisition_plan(catalog: Mapping[str, Any]) -> dict[str, Any]:
    active = validate_catalog(catalog)
    by_id = {c["candidate_id"]: c for c in active["candidates"]}
    pair = active["recommended_pair"]
    dev = by_id[pair["development_candidate_id"]]
    final = by_id[pair["final_holdout_candidate_id"]]

    if "DEVELOPMENT" not in dev["role_eligibility"]:
        raise StageCDatasetQualificationError("recommended development candidate is not eligible")
    if "FINAL_HOLDOUT" not in final["role_eligibility"]:
        raise StageCDatasetQualificationError("recommended final candidate is not eligible")
    if dev["source_id"] == final["source_id"]:
        raise StageCDatasetQualificationError("development/final source_id must differ")
    if "html" not in dev["capture_format"] or "html" not in final["capture_format"]:
        raise StageCDatasetQualificationError("recommended pair must provide captured HTML")
    if dev["license"] != "CC BY 4.0" or final["license"] != "CC BY 4.0":
        raise StageCDatasetQualificationError("recommended pair requires reviewed reuse licenses")

    dcounts = dev["class_counts"]
    fcounts = final["class_counts"]
    if dcounts.get("legitimate", 0) < 381 or dcounts.get("phishing", 0) < 1:
        raise StageCDatasetQualificationError("development candidate class coverage insufficient")
    if fcounts.get("legitimate", 0) < 381 or fcounts.get("phishing", 0) < 1:
        raise StageCDatasetQualificationError("final candidate class coverage insufficient")

    _, dev_end = _period_bounds(dev)
    final_start, _ = _period_bounds(final)
    if dev_end is None or final_start is None or final_start <= dev_end:
        raise StageCDatasetQualificationError(
            "recommended final source must begin after primary development collection ends"
        )

    return {
        "schema_version": PLAN_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": False,
        "downloads_authorized": False,
        "development": {
            "candidate_id": dev["candidate_id"],
            "source_id": dev["source_id"],
            "doi": dev["doi"],
            "license": dev["license"],
            "expected_class_counts": dev["class_counts"],
            "landing_page": dev["landing_page"],
            "acquisition_state": "QUALIFIED_NOT_DOWNLOADED",
        },
        "final_holdout": {
            "candidate_id": final["candidate_id"],
            "source_id": final["source_id"],
            "doi": final["doi"],
            "license": final["license"],
            "expected_class_counts": final["class_counts"],
            "landing_page": final["landing_page"],
            "acquisition_state": "QUALIFIED_LOCKED_NOT_DOWNLOADED",
            "allowed_uses_before_final_freeze": [
                "LICENSE_VERIFICATION",
                "FILE_INTEGRITY_VERIFICATION",
                "SCHEMA_VERIFICATION",
                "IDENTITY_INDEX_BUILD",
                "CONTAMINATION_AUDIT"
            ],
            "prohibited_uses_before_final_freeze": [
                "FEATURE_SELECTION",
                "MODEL_SELECTION",
                "CALIBRATION",
                "THRESHOLD_SELECTION",
                "MODEL_SCORING",
                "ERROR_ANALYSIS"
            ],
        },
        "source_independent": True,
        "strict_temporal_order": {
            "development_end": dev_end.isoformat(),
            "final_start": final_start.isoformat(),
            "satisfied": True,
        },
        "next_gate": "VERIFY_REMOTE_FILES_AND_FREEZE_DOWNLOAD_MANIFESTS",
    }
