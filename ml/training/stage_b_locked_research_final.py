"""Stage B Task 23: one-time locked research final-test evaluation.

This wrapper reuses the existing locked Stage B final evaluator, but enforces the
single-source archive research protocol around it.

Key properties:
- Task 22 benchmark + calibration must already be frozen and hash-consistent.
- The final test is never used for selection/calibration/threshold selection.
- A dataset-specific lock receipt is created atomically BEFORE test scoring.
- If scoring crashes, the PREPARED receipt remains and rerun is refused.
- A completed result remains research-only, integration-ineligible, and
  deployment_authorized=false regardless of metrics.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from ml.data.stage_b_features import validate_feature_dataset
from ml.training.stage_b_calibration import (
    _feature_identity,
    validate_calibration_policy,
)
from ml.training.stage_b_final_evaluation import (
    FinalEvaluationError,
    _canonical_hash as final_canonical_hash,
    _validate_chain as validate_final_chain,
    final_evaluate_stage_b_model,
)
from ml.training.stage_b_research_benchmark import (
    RESEARCH_BENCHMARK_SCHEMA,
    RESEARCH_PROTOCOL,
    canonical_hash,
)

RESEARCH_FINAL_SCHEMA = "stage-b-locked-research-final-evaluation-1"
LOCK_SCHEMA = "stage-b-locked-research-final-test-lock-1"


class ResearchFinalError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ResearchFinalError(f"required JSON file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResearchFinalError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ResearchFinalError(f"JSON root must be an object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _test_identity(feature_data: Mapping[str, Any]) -> dict[str, Any]:
    validated = validate_feature_dataset(feature_data)
    rows = validated["partitions"]["test"]["records"]
    material = [
        {
            "sample_id": row["sample_id"],
            "ground_truth": row["ground_truth"],
            "observed_at": row["observed_at"],
            "artifact_group": row["artifact_group"],
            "domain_group": row["domain_group"],
            "brand_group": row.get("brand_group"),
            "source_groups": row["source_groups"],
            "feature_vector_sha256": hashlib.sha256(
                json.dumps(
                    row["feature_vector"],
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
        }
        for row in sorted(rows, key=lambda row: row["sample_id"])
    ]
    return {
        "test_samples": len(material),
        "test_partition_identity_sha256": canonical_hash(material),
    }


def validate_research_final_chain(
    *,
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    task22: Mapping[str, Any],
    calibration_policy: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
    except Exception as exc:
        raise ResearchFinalError(f"invalid feature dataset: {exc}") from exc

    if task22.get("schema_version") != RESEARCH_BENCHMARK_SCHEMA:
        raise ResearchFinalError("unsupported Task 22 report schema")
    if task22.get("status") != "PASS":
        raise ResearchFinalError("Task 22 report is not PASS")
    if task22.get("research_protocol") != RESEARCH_PROTOCOL:
        raise ResearchFinalError("Task 22 research protocol mismatch")
    if task22.get("research_only") is not True:
        raise ResearchFinalError("Task 22 must remain research_only=true")
    if task22.get("deployment_authorized") is not False:
        raise ResearchFinalError("Task 22 must explicitly deny deployment")
    if task22.get("integration_eligible") is not False:
        raise ResearchFinalError("Task 22 must remain integration-ineligible")
    if task22.get("production_readiness_equivalent") is not False:
        raise ResearchFinalError("Task 22 cannot claim production-readiness equivalence")

    test_guard = task22.get("test_partition")
    if not isinstance(test_guard, Mapping):
        raise ResearchFinalError("Task 22 test guard is missing")
    expected_guard = {
        "status": "LOCKED_NOT_USED",
        "used_for_model_selection": False,
        "used_for_calibration": False,
        "used_for_threshold_selection": False,
        "scored": False,
    }
    if dict(test_guard) != expected_guard:
        raise ResearchFinalError("Task 22 did not preserve an untouched final test")

    identity = _feature_identity(validated)
    if task22.get("feature_dataset_identity") != identity:
        raise ResearchFinalError("Task 22 feature identity mismatch")
    dataset_hash = canonical_hash(validated)
    if task22.get("feature_dataset_sha256") != dataset_hash:
        raise ResearchFinalError("Task 22 feature content hash mismatch")
    if readiness.get("feature_dataset_sha256") != dataset_hash:
        raise ResearchFinalError("readiness feature content hash mismatch")

    benchmark = task22.get("benchmark")
    calibration = task22.get("calibration")
    if not isinstance(benchmark, Mapping) or not isinstance(calibration, Mapping):
        raise ResearchFinalError("Task 22 underlying benchmark/calibration evidence missing")
    if task22.get("benchmark_sha256") != canonical_hash(benchmark):
        raise ResearchFinalError("Task 22 benchmark hash mismatch")
    if task22.get("calibration_sha256") != canonical_hash(calibration):
        raise ResearchFinalError("Task 22 calibration hash mismatch")

    policy = validate_calibration_policy(calibration_policy)
    try:
        validate_final_chain(validated, readiness, benchmark, calibration, policy)
    except FinalEvaluationError as exc:
        raise ResearchFinalError(str(exc)) from exc

    return {
        "validated_features": validated,
        "benchmark": dict(benchmark),
        "calibration": dict(calibration),
        "policy": policy,
        "feature_dataset_sha256": dataset_hash,
        **_test_identity(validated),
    }


def lock_path_for_dataset(lock_root: Path, feature_dataset_sha256: str) -> Path:
    if not isinstance(feature_dataset_sha256, str) or len(feature_dataset_sha256) != 64:
        raise ResearchFinalError("invalid feature dataset hash for lock identity")
    return lock_root / f"{feature_dataset_sha256}.json"


def acquire_final_test_lock(
    *,
    path: Path,
    chain: Mapping[str, Any],
    feature_path: Path,
    readiness_path: Path,
    task22_path: Path,
    calibration_policy_path: Path,
) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": LOCK_SCHEMA,
        "status": "PREPARED",
        "created_at": _utc_now(),
        "feature_dataset_sha256": chain["feature_dataset_sha256"],
        "test_partition_identity_sha256": chain["test_partition_identity_sha256"],
        "test_samples": chain["test_samples"],
        "inputs": {
            "feature_file_sha256": sha256_file(feature_path),
            "readiness_file_sha256": sha256_file(readiness_path),
            "task22_file_sha256": sha256_file(task22_path),
            "calibration_policy_file_sha256": sha256_file(calibration_policy_path),
            "benchmark_sha256": canonical_hash(chain["benchmark"]),
            "calibration_sha256": canonical_hash(chain["calibration"]),
        },
        "meaning": (
            "The locked research final-test evaluation has been authorized for "
            "this exact feature/test identity. Existence of this receipt forbids "
            "another final-test scoring attempt, including after interruption."
        ),
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags)
    except FileExistsError as exc:
        raise ResearchFinalError(
            f"research final test is already locked/consumed for this dataset: {path}"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        # Fail closed: intentionally do not delete a partially established lock.
        raise
    return payload


def finalize_lock(
    path: Path,
    prepared: Mapping[str, Any],
    *,
    result: Mapping[str, Any],
    output_path: Path,
) -> dict[str, Any]:
    finalized = dict(prepared)
    finalized.update({
        "status": "FINALIZED",
        "finalized_at": _utc_now(),
        "result_schema_version": result.get("schema_version"),
        "result_sha256": canonical_hash(result),
        "result_file": str(output_path),
        "research_only": True,
        "deployment_authorized": False,
    })
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(finalized, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)
    return finalized


def run_locked_research_final(
    *,
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    task22: Mapping[str, Any],
    calibration_policy: Mapping[str, Any],
) -> dict[str, Any]:
    chain = validate_research_final_chain(
        feature_data=feature_data,
        readiness=readiness,
        task22=task22,
        calibration_policy=calibration_policy,
    )
    try:
        underlying = final_evaluate_stage_b_model(
            chain["validated_features"],
            readiness,
            chain["benchmark"],
            chain["calibration"],
            chain["policy"],
        )
    except FinalEvaluationError as exc:
        raise ResearchFinalError(str(exc)) from exc

    usage = underlying.get("data_usage")
    if not isinstance(usage, Mapping):
        raise ResearchFinalError("underlying final evaluator omitted data-use evidence")
    expected_false = (
        "test_used_for_model_selection",
        "test_used_for_calibration",
        "test_used_for_threshold_selection",
    )
    if usage.get("test_role") != "FINAL_EVALUATION_ONLY":
        raise ResearchFinalError("final test role changed")
    if any(usage.get(key) is not False for key in expected_false):
        raise ResearchFinalError("final test was reused for tuning")

    primary = task22.get("primary_research_operating_point")
    if not isinstance(primary, Mapping):
        raise ResearchFinalError("Task 22 primary research operating point missing")

    fixed = underlying.get("fixed_operating_point")
    if not isinstance(fixed, Mapping):
        raise ResearchFinalError("underlying fixed operating-point evidence missing")

    return {
        "schema_version": RESEARCH_FINAL_SCHEMA,
        "status": "PASS",
        "research_protocol": RESEARCH_PROTOCOL,
        "research_only": True,
        "deployment_authorized": False,
        "integration_eligible": False,
        "production_readiness_equivalent": False,
        "feature_dataset_sha256": chain["feature_dataset_sha256"],
        "test_partition_identity_sha256": chain["test_partition_identity_sha256"],
        "test_samples": chain["test_samples"],
        "task22_sha256": canonical_hash(task22),
        "benchmark_sha256": canonical_hash(chain["benchmark"]),
        "calibration_sha256": canonical_hash(chain["calibration"]),
        "test_use": {
            "role": "ONE_TIME_LOCKED_RESEARCH_FINAL_EVALUATION",
            "used_for_model_selection": False,
            "used_for_calibration": False,
            "used_for_threshold_selection": False,
            "eligible_for_future_tuning": False,
        },
        "selected_candidate": underlying.get("selected_candidate"),
        "threshold_free_metrics": underlying.get("threshold_free_metrics"),
        "fixed_research_operating_point": {
            **dict(fixed),
            "deployment_authorized": False,
            "interpretation": (
                "One-time locked research final-test evidence for the frozen "
                "single-source archive protocol. Metrics cannot authorize "
                "deployment or be used to retune this candidate."
            ),
        },
        "underlying_final_evaluation_sha256": canonical_hash(underlying),
        "underlying_final_evaluation": underlying,
        "next_gate": {
            "name": "RESEARCH_EVIDENCE_REVIEW",
            "automatic_model_promotion": False,
            "automatic_release_candidate_export": False,
            "deployment_authority": False,
            "test_may_be_reopened_for_tuning": False,
        },
        "limitations": [
            "This is one archived dataset source; source independence is relaxed.",
            "Archived browser replay does not reproduce live network/server/user context.",
            "The test set is consumed by this one-time evaluation and must not be reused for tuning.",
            "PASS means the frozen evaluation executed consistently; it is not production approval.",
            "No result from this research protocol can authorize autonomous blocking or deployment.",
        ],
    }
