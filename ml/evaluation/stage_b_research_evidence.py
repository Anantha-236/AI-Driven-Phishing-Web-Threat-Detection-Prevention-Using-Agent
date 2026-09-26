"""Stage B Task 24: freeze and verify the scaled research evidence chain.

This verifier does not train, score, calibrate, export, install, or promote a
model. It only validates the already-frozen Tasks 20-23 artifacts and produces
a hash-pinned research evidence manifest.

PASS means the research protocol executed consistently. It is explicitly not a
deployment or production-readiness decision.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

TASK20_SCHEMA = "stage-b-scaled-candidate-assembly-1"
TASK21_SCHEMA = "stage-b-scaled-replay-run-1"
TASK22_SCHEMA = "stage-b-research-benchmark-calibration-1"
TASK23_SCHEMA = "stage-b-locked-research-final-evaluation-1"
LOCK_SCHEMA = "stage-b-locked-research-final-test-lock-1"
EVIDENCE_SCHEMA = "stage-b-scaled-research-evidence-1"


class ResearchEvidenceError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ResearchEvidenceError(f"required evidence file not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResearchEvidenceError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ResearchEvidenceError(f"JSON root must be an object: {path}")
    return value


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_research_guard(name: str, payload: Mapping[str, Any]) -> None:
    if payload.get("research_only") is not True:
        raise ResearchEvidenceError(f"{name} lost research_only=true")
    if payload.get("deployment_authorized") is not False:
        raise ResearchEvidenceError(f"{name} must keep deployment_authorized=false")


def verify_evidence_chain(
    *,
    task20_report: Mapping[str, Any],
    task21_report: Mapping[str, Any],
    task21_readiness: Mapping[str, Any],
    task22_report: Mapping[str, Any],
    task23_report: Mapping[str, Any],
    final_lock: Mapping[str, Any],
) -> dict[str, Any]:
    if task20_report.get("schema_version") != TASK20_SCHEMA:
        raise ResearchEvidenceError("Task 20 report schema mismatch")
    if task20_report.get("status") != "PASS":
        raise ResearchEvidenceError("Task 20 report is not PASS")
    _require_research_guard("Task 20", task20_report)
    if task20_report.get("split_count_readiness", {}).get("status") != "PASS":
        raise ResearchEvidenceError("Task 20 split-count readiness is not PASS")

    if task21_report.get("status") != "PASS":
        raise ResearchEvidenceError("Task 21 run report is not PASS")
    _require_research_guard("Task 21", task21_report)
    if task21_report.get("training_allowed_for_research_benchmark") is not True:
        raise ResearchEvidenceError("Task 21 did not authorize research benchmarking")

    if task21_readiness.get("status") != "PASS":
        raise ResearchEvidenceError("Task 21 readiness is not PASS")
    _require_research_guard("Task 21 readiness", task21_readiness)
    if task21_readiness.get("training_allowed") is not True:
        raise ResearchEvidenceError("Task 21 readiness does not allow research training")
    if task21_readiness.get("production_readiness_equivalent") is not False:
        raise ResearchEvidenceError("Task 21 readiness cannot claim production equivalence")

    if task22_report.get("schema_version") != TASK22_SCHEMA:
        raise ResearchEvidenceError("Task 22 report schema mismatch")
    if task22_report.get("status") != "PASS":
        raise ResearchEvidenceError("Task 22 report is not PASS")
    _require_research_guard("Task 22", task22_report)
    if task22_report.get("integration_eligible") is not False:
        raise ResearchEvidenceError("Task 22 must remain integration-ineligible")
    test22 = task22_report.get("test_partition")
    if not isinstance(test22, Mapping) or test22.get("status") != "LOCKED_NOT_USED":
        raise ResearchEvidenceError("Task 22 did not keep final test locked")
    if test22.get("scored") is not False:
        raise ResearchEvidenceError("Task 22 scored the final test")

    if task23_report.get("schema_version") != TASK23_SCHEMA:
        raise ResearchEvidenceError("Task 23 report schema mismatch")
    if task23_report.get("status") != "PASS":
        raise ResearchEvidenceError("Task 23 report is not PASS")
    _require_research_guard("Task 23", task23_report)
    if task23_report.get("integration_eligible") is not False:
        raise ResearchEvidenceError("Task 23 must remain integration-ineligible")
    if task23_report.get("production_readiness_equivalent") is not False:
        raise ResearchEvidenceError("Task 23 cannot claim production equivalence")

    if final_lock.get("schema_version") != LOCK_SCHEMA:
        raise ResearchEvidenceError("Task 23 lock schema mismatch")
    if final_lock.get("status") != "FINALIZED":
        raise ResearchEvidenceError("Task 23 final-test lock is not FINALIZED")
    if final_lock.get("research_only") is not True:
        raise ResearchEvidenceError("Task 23 final lock lost research-only guard")
    if final_lock.get("deployment_authorized") is not False:
        raise ResearchEvidenceError("Task 23 final lock must deny deployment")

    dataset_hash = task23_report.get("feature_dataset_sha256")
    if not isinstance(dataset_hash, str) or len(dataset_hash) != 64:
        raise ResearchEvidenceError("Task 23 feature dataset hash is invalid")
    if task22_report.get("feature_dataset_sha256") != dataset_hash:
        raise ResearchEvidenceError("Task 22/23 feature dataset identity mismatch")
    if task21_readiness.get("feature_dataset_sha256") != dataset_hash:
        raise ResearchEvidenceError("Task 21/23 feature dataset identity mismatch")
    if final_lock.get("feature_dataset_sha256") != dataset_hash:
        raise ResearchEvidenceError("Task 23 lock feature dataset identity mismatch")

    test_identity = task23_report.get("test_partition_identity_sha256")
    if final_lock.get("test_partition_identity_sha256") != test_identity:
        raise ResearchEvidenceError("Task 23 result/lock test identity mismatch")
    if final_lock.get("result_sha256") != canonical_hash(task23_report):
        raise ResearchEvidenceError("Task 23 lock result hash does not match final report")

    if task23_report.get("task22_sha256") != canonical_hash(task22_report):
        raise ResearchEvidenceError("Task 23 does not pin the exact Task 22 report")
    if task23_report.get("benchmark_sha256") != task22_report.get("benchmark_sha256"):
        raise ResearchEvidenceError("Task 22/23 benchmark hash mismatch")
    if task23_report.get("calibration_sha256") != task22_report.get("calibration_sha256"):
        raise ResearchEvidenceError("Task 22/23 calibration hash mismatch")

    task23_test_use = task23_report.get("test_use")
    if not isinstance(task23_test_use, Mapping):
        raise ResearchEvidenceError("Task 23 test-use evidence missing")
    if task23_test_use.get("role") != "ONE_TIME_LOCKED_RESEARCH_FINAL_EVALUATION":
        raise ResearchEvidenceError("Task 23 final-test role mismatch")
    for key in (
        "used_for_model_selection",
        "used_for_calibration",
        "used_for_threshold_selection",
        "eligible_for_future_tuning",
    ):
        if task23_test_use.get(key) is not False:
            raise ResearchEvidenceError(f"Task 23 invalid test-use flag: {key}")

    return {
        "status": "PASS",
        "schema_version": EVIDENCE_SCHEMA,
        "research_only": True,
        "deployment_authorized": False,
        "integration_eligible": False,
        "production_readiness_equivalent": False,
        "feature_dataset_sha256": dataset_hash,
        "test_partition_identity_sha256": test_identity,
        "test_samples": task23_report.get("test_samples"),
        "selected_candidate": task23_report.get("selected_candidate"),
        "evidence_hashes": {
            "task20_report_sha256": canonical_hash(task20_report),
            "task21_report_sha256": canonical_hash(task21_report),
            "task21_readiness_sha256": canonical_hash(task21_readiness),
            "task22_report_sha256": canonical_hash(task22_report),
            "task23_report_sha256": canonical_hash(task23_report),
            "task23_lock_sha256": canonical_hash(final_lock),
        },
        "final_test": {
            "consumed_once": True,
            "may_be_reopened_for_tuning": False,
            "lock_status": "FINALIZED",
        },
        "conclusion_scope": (
            "PASS verifies internal consistency and reproducibility of the frozen "
            "single-source archived-browser-replay research protocol only."
        ),
        "limitations": [
            "The evidence is derived from one archived dataset source.",
            "Source independence is intentionally relaxed and production-readiness equivalence is false.",
            "Archived replay does not recreate live network, server, user, or adversarial context.",
            "The locked test has been consumed and cannot be reused for tuning.",
            "No Task 24 PASS may authorize deployment, browser decision authority, or automatic release-candidate promotion.",
        ],
    }
