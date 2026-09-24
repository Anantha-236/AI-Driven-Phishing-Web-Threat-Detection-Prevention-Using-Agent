"""Stage B release-candidate freeze and ONNX parity gate.

This stage does not deploy a model and does not re-score the final-test partition.
It reconstructs the already-selected/calibrated chain from train + selection +
calibration, verifies Task 10 chain evidence, exports a local ONNX candidate, and
proves Python <-> ONNX Runtime probability parity on non-test vectors.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import onnx
import onnxruntime as ort
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from skl2onnx import convert_sklearn, get_latest_tested_opset_version
from skl2onnx.common.data_types import FloatTensorType

from ml.data.stage_b_features import validate_feature_dataset
from ml.training.stage_b_calibration import (
    CALIBRATION_SCHEMA,
    DEFAULT_CALIBRATION_POLICY,
    _feature_identity,
    _rows,
    _scores_hash,
    _selected_spec,
    _xy,
    validate_calibration_policy,
)
from ml.training.stage_b_final_evaluation import (
    FINAL_EVALUATION_SCHEMA,
    _validate_chain as _validate_pre_final_chain,
)

RELEASE_CANDIDATE_SCHEMA = "stage-b-release-candidate-1"
PARITY_SCHEMA = "stage-b-onnx-parity-1"
PARITY_TOLERANCE = 1e-5
PARITY_PARTITIONS = ("train", "selection", "calibration")
MODEL_FILENAME = "stage-b-contextual-candidate.onnx"
MANIFEST_FILENAME = "stage-b-release-manifest.json"
PARITY_FILENAME = "stage-b-parity-vectors.json"


class ReleaseCandidateError(ValueError):
    """Raised when the Stage B release candidate cannot be frozen safely."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_final_report(
    feature_data: Mapping[str, Any],
    readiness: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    calibration: Mapping[str, Any],
    final_evaluation: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    _validate_pre_final_chain(feature_data, readiness, benchmark, calibration, policy)
    dataset_hash = _canonical_hash(feature_data)

    if final_evaluation.get("schema_version") != FINAL_EVALUATION_SCHEMA:
        raise ReleaseCandidateError("unsupported final-evaluation schema")
    if final_evaluation.get("status") != "PASS":
        raise ReleaseCandidateError("PASS final-evaluation report is required")
    if final_evaluation.get("feature_dataset_sha256") != dataset_hash:
        raise ReleaseCandidateError("final evaluation does not match feature dataset contents")
    if final_evaluation.get("feature_dataset_identity") != _feature_identity(feature_data):
        raise ReleaseCandidateError("final evaluation does not match feature dataset identity")
    if final_evaluation.get("selected_candidate") != benchmark.get("selected_candidate"):
        raise ReleaseCandidateError("final evaluation selected candidate does not match benchmark")
    if final_evaluation.get("benchmark_protocol_sha256") != benchmark.get("benchmark_protocol_sha256"):
        raise ReleaseCandidateError("final evaluation does not match benchmark protocol")
    if final_evaluation.get("calibration_policy_sha256") != calibration.get("calibration_policy_sha256"):
        raise ReleaseCandidateError("final evaluation does not match calibration policy")
    if final_evaluation.get("reproduced_calibration_scores_sha256") != calibration.get("calibration_scores_sha256"):
        raise ReleaseCandidateError("final evaluation did not reproduce Task 9 calibration scores")
    usage = final_evaluation.get("data_usage")
    if not isinstance(usage, Mapping) or usage.get("test_role") != "FINAL_EVALUATION_ONLY":
        raise ReleaseCandidateError("final evaluation data-use declaration is invalid")
    for key in (
        "test_used_for_model_selection",
        "test_used_for_calibration",
        "test_used_for_threshold_selection",
    ):
        if usage.get(key) is not False:
            raise ReleaseCandidateError("final evaluation reports prohibited test reuse")


def _reconstruct_calibrated_model(
    feature_data: Mapping[str, Any],
    benchmark: Mapping[str, Any],
    calibration: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> CalibratedClassifierCV:
    selected = str(benchmark["selected_candidate"])
    if calibration.get("selected_candidate") != selected:
        raise ReleaseCandidateError("calibration selected candidate does not match benchmark")
    spec = _selected_spec(selected)
    x_refit, y_refit = _xy(feature_data, ("train", "selection"))
    calibration_rows = _rows(feature_data, "calibration")
    x_calibration, y_calibration = _xy(feature_data, ("calibration",))

    base_model = spec.factory()
    base_model.fit(x_refit, y_refit)
    calibrator = CalibratedClassifierCV(
        estimator=FrozenEstimator(base_model),
        method=policy["method"],
    )
    calibrator.fit(x_calibration, y_calibration)
    scores = np.asarray(calibrator.predict_proba(x_calibration)[:, 1], dtype=float)
    if _scores_hash(calibration_rows, scores) != calibration.get("calibration_scores_sha256"):
        raise ReleaseCandidateError("reconstructed calibration scores do not match Task 9")
    return calibrator


def _unwrap_frozen_for_conversion(calibrator: CalibratedClassifierCV) -> CalibratedClassifierCV:
    """Create a conversion-only clone without refitting anything.

    sklearn-onnx supports CalibratedClassifierCV but FrozenEstimator itself is not
    a portable runtime component. The fitted underlying estimator is therefore
    unwrapped only in a deep-copied serialization view. Prediction parity with
    the authoritative calibrated model is checked before ONNX conversion.
    """
    exportable = copy.deepcopy(calibrator)
    if isinstance(getattr(exportable, "estimator", None), FrozenEstimator):
        exportable.estimator = exportable.estimator.estimator
    for fitted in getattr(exportable, "calibrated_classifiers_", []):
        if isinstance(getattr(fitted, "estimator", None), FrozenEstimator):
            fitted.estimator = fitted.estimator.estimator
    return exportable


def _parity_rows(feature_data: Mapping[str, Any], per_partition: int = 8) -> list[Mapping[str, Any]]:
    chosen: list[Mapping[str, Any]] = []
    for partition in PARITY_PARTITIONS:
        rows = sorted(_rows(feature_data, partition), key=lambda row: str(row["sample_id"]))
        chosen.extend(rows[: min(per_partition, len(rows))])
    if not chosen:
        raise ReleaseCandidateError("no non-test rows are available for ONNX parity")
    return chosen


def _find_probability_output(
    session: ort.InferenceSession,
    values: np.ndarray,
    input_name: str,
) -> tuple[str, np.ndarray]:
    outputs = session.run(None, {input_name: values.astype(np.float32)})
    metadata = session.get_outputs()
    candidates: list[tuple[str, np.ndarray]] = []
    for meta, value in zip(metadata, outputs, strict=True):
        array = np.asarray(value)
        if (
            array.ndim == 2
            and array.shape[0] == values.shape[0]
            and array.shape[1] == 2
            and np.issubdtype(array.dtype, np.floating)
            and np.isfinite(array).all()
        ):
            row_sums = np.asarray(array, dtype=float).sum(axis=1)
            if np.all(array >= -1e-6) and np.all(array <= 1 + 1e-6) and np.allclose(row_sums, 1.0, atol=1e-4):
                candidates.append((meta.name, np.asarray(array, dtype=float)))
    if len(candidates) != 1:
        raise ReleaseCandidateError(
            f"expected exactly one [N,2] ONNX probability output, found {len(candidates)}"
        )
    return candidates[0]


def _opsets(model: onnx.ModelProto) -> dict[str, int]:
    return {entry.domain or "ai.onnx": int(entry.version) for entry in model.opset_import}


def freeze_stage_b_release_candidate(
    feature_data: Mapping[str, Any],
    readiness_audit: Mapping[str, Any],
    benchmark_report: Mapping[str, Any],
    calibration_report: Mapping[str, Any],
    final_evaluation_report: Mapping[str, Any],
    output_dir: str | Path,
    calibration_policy: Mapping[str, Any] | None = None,
    *,
    parity_tolerance: float = PARITY_TOLERANCE,
) -> dict[str, Any]:
    try:
        validated = validate_feature_dataset(feature_data)
    except Exception as exc:
        raise ReleaseCandidateError(f"invalid feature dataset: {exc}") from exc
    if validated.get("feature_version") != "context-features-1":
        raise ReleaseCandidateError("release candidate requires context-features-1")
    if validated.get("representation") != "contextual-flat":
        raise ReleaseCandidateError("release candidate requires contextual-flat representation")
    feature_names = validated.get("feature_names")
    if not isinstance(feature_names, list) or not feature_names or any(not isinstance(v, str) for v in feature_names):
        raise ReleaseCandidateError("feature_names are missing or invalid")

    active_policy = validate_calibration_policy(calibration_policy or DEFAULT_CALIBRATION_POLICY)
    try:
        _validate_final_report(
            validated,
            readiness_audit,
            benchmark_report,
            calibration_report,
            final_evaluation_report,
            active_policy,
        )
    except ReleaseCandidateError:
        raise
    except Exception as exc:
        raise ReleaseCandidateError(str(exc)) from exc

    calibrator = _reconstruct_calibrated_model(
        validated, benchmark_report, calibration_report, active_policy
    )
    parity_rows = _parity_rows(validated)
    parity_x = np.asarray([row["feature_vector"] for row in parity_rows], dtype=np.float32)
    python_scores = np.asarray(calibrator.predict_proba(parity_x)[:, 1], dtype=float)

    exportable = _unwrap_frozen_for_conversion(calibrator)
    exportable_scores = np.asarray(exportable.predict_proba(parity_x)[:, 1], dtype=float)
    if not np.allclose(python_scores, exportable_scores, atol=1e-12, rtol=0):
        raise ReleaseCandidateError("conversion view changed calibrated Python probabilities")

    try:
        onnx_model = convert_sklearn(
            exportable,
            name="CAPSTONE-1 Stage B contextual release candidate",
            initial_types=[("contextual_features", FloatTensorType([None, len(feature_names)]))],
            target_opset=get_latest_tested_opset_version(),
            options={id(exportable): {"zipmap": False}},
        )
        onnx.checker.check_model(onnx_model)
        model_bytes = onnx_model.SerializeToString()
    except Exception as exc:
        raise ReleaseCandidateError(
            f"selected calibrated candidate cannot be converted to verified ONNX: {exc}"
        ) from exc

    try:
        session = ort.InferenceSession(model_bytes, providers=["CPUExecutionProvider"])
    except Exception as exc:
        raise ReleaseCandidateError(f"ONNX Runtime rejected exported model: {exc}") from exc

    inputs = session.get_inputs()
    if len(inputs) != 1:
        raise ReleaseCandidateError("release ONNX must expose exactly one input tensor")
    input_name = inputs[0].name
    probability_output_name, probabilities = _find_probability_output(session, parity_x, input_name)
    onnx_scores = probabilities[:, 1]
    max_error = float(np.max(np.abs(onnx_scores - python_scores)))
    if max_error > parity_tolerance:
        raise ReleaseCandidateError(
            f"Python/ONNX calibrated probability parity failed: {max_error} > {parity_tolerance}"
        )

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    targets = [output / MODEL_FILENAME, output / MANIFEST_FILENAME, output / PARITY_FILENAME]
    if any(path.exists() for path in targets):
        raise ReleaseCandidateError("release-candidate output already exists; refusing overwrite")

    model_sha = _sha256_bytes(model_bytes)
    final_report_sha = _canonical_hash(final_evaluation_report)
    primary_cap = float(calibration_report["threshold_selection"]["primary_fpr_cap"])
    primary_key = f"fpr_le_{primary_cap:g}"
    primary = calibration_report["threshold_selection"]["operating_points"][primary_key]
    final_fixed = final_evaluation_report["fixed_operating_point"]
    calibration_authorized = bool(calibration_report["threshold_selection"]["deployment_threshold_authorized"])
    final_bound_supported = (
        isinstance(final_fixed.get("fpr_wilson_95"), list)
        and len(final_fixed["fpr_wilson_95"]) == 2
        and float(final_fixed["fpr_wilson_95"][1]) <= primary_cap
    )
    integration_eligible = calibration_authorized and final_bound_supported

    parity_payload = {
        "schema_version": PARITY_SCHEMA,
        "feature_version": validated["feature_version"],
        "feature_names": feature_names,
        "test_partition_used": False,
        "partitions_used": list(PARITY_PARTITIONS),
        "vectors": [
            {
                "sample_id": row["sample_id"],
                "partition": row["partition"],
                "feature_vector": [float(v) for v in row["feature_vector"]],
                "expected_calibrated_probability": float(score),
            }
            for row, score in zip(parity_rows, python_scores, strict=True)
        ],
    }

    reasons: list[str] = []
    if not calibration_authorized:
        reasons.append("Task 9 did not authorize the primary low-FPR threshold.")
    if not final_bound_supported:
        reasons.append("Task 10 final-test Wilson FPR upper bound exceeds the frozen primary cap.")
    reasons.append("Task 12 browser-WASM integration and end-to-end extension parity are not yet complete.")

    manifest = {
        "schema_version": RELEASE_CANDIDATE_SCHEMA,
        "status": "PASS",
        "model_id": f"stage-b-{benchmark_report['selected_candidate']}-{model_sha[:12]}",
        "selected_candidate": benchmark_report["selected_candidate"],
        "candidate_family": calibration_report["candidate_family"],
        "candidate_parameters": calibration_report["candidate_parameters"],
        "representation": validated["representation"],
        "feature_version": validated["feature_version"],
        "feature_names": feature_names,
        "feature_contract_sha256": validated["feature_contract_sha256"],
        "extractor_source_sha256": validated["extractor_source_sha256"],
        "feature_dataset_sha256": _canonical_hash(validated),
        "readiness_policy_sha256": readiness_audit["policy_sha256"],
        "benchmark_protocol_sha256": benchmark_report["benchmark_protocol_sha256"],
        "calibration_policy_sha256": calibration_report["calibration_policy_sha256"],
        "final_evaluation_sha256": final_report_sha,
        "onnx": {
            "filename": MODEL_FILENAME,
            "sha256": model_sha,
            "input_name": input_name,
            "probability_output_name": probability_output_name,
            "positive_class_index": 1,
            "opsets": _opsets(onnx_model),
        },
        "parity": {
            "schema_version": PARITY_SCHEMA,
            "filename": PARITY_FILENAME,
            "status": "PASS",
            "vectors": len(parity_rows),
            "partitions_used": list(PARITY_PARTITIONS),
            "test_partition_used": False,
            "tolerance": float(parity_tolerance),
            "maximum_absolute_probability_error": max_error,
        },
        "operating_point": {
            "threshold": float(primary["threshold"]),
            "primary_fpr_cap": primary_cap,
            "calibration_deployment_authorized": calibration_authorized,
            "final_test_fpr_wilson_95": final_fixed.get("fpr_wilson_95"),
        },
        "release_gate": {
            "integration_eligible": integration_eligible,
            "deploy": False,
            "autonomous_blocking": False,
            "reasons": reasons,
        },
        "limitations": [
            "This artifact freeze does not copy files into browser-extension/assets.",
            "Parity uses train/selection/calibration vectors only and does not reopen the locked final-test scores.",
            "Node/browser-WASM runtime integration is a separate gate.",
            "Release-candidate PASS proves serialization parity, not production deployment approval.",
        ],
    }

    (output / MODEL_FILENAME).write_bytes(model_bytes)
    (output / PARITY_FILENAME).write_text(json.dumps(parity_payload, indent=2) + "\n", encoding="utf-8")
    (output / MANIFEST_FILENAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
