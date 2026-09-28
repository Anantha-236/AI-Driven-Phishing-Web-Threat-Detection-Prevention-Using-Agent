"""Stage C Task 15 — authorize controlled selection-label evaluation.

This gate verifies the frozen Task-14 label-blind scores and the exact complete
selection labels. It freezes their join identity and authorizes a later task to
compute selection metrics.

Task 15 itself computes no model-quality metric, ranks no candidate, chooses no
candidate, freezes no threshold, accesses no calibration rows, and touches no
final holdout.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

AUTH_SCHEMA = "stage-c-selection-label-evaluation-authorization-1"

EXPECTED_TASK13_AUTHORIZATION_SHA256 = "a48f625c3b9c96fdebbd51729c197b1d9a87f2255f1a52db74715e4e1674a9c5"
EXPECTED_TASK14_SCORE_DATASET_SHA256 = "92bc6429d8a61f3aeed206967c9df526e60388859e742be5eaa3ea0faad822d8"
EXPECTED_TASK14_SCORING_MANIFEST_SHA256 = "430654bf68aed282069bd21cc65b454e54c6782dcd31a1a811994ac06a565f1f"
EXPECTED_TASK14_GIT_HEAD = "781a8b53c71a744af9fb887b5a096116a7bfed1f"
EXPECTED_FEATURE_DATASET_SHA256 = "dffbec460c4fb39a91003186cfbc86b60926813f6c936f79675277a0cc6079a4"

EXPECTED_TOTAL_ROWS = 73777
EXPECTED_SELECTION_COUNT = 20710
EXPECTED_SELECTION_SAMPLE_SET_SHA256 = "0cc84274558ee32889b114633e14782fe14c9dd17e933b8faa929efeab65c0cd"
EXPECTED_SELECTION_FEATURE_MATRIX_SHA256 = "31b58dd8900bddac87a7b9bcf8916d539f8b2c4326bbfe2b45919d521b4d03b0"
EXPECTED_SELECTION_LABEL_COUNTS = {"legitimate": 19641, "phishing": 1069}
EXPECTED_CANDIDATE_COUNT = 4
EXPECTED_SCORE_ROWS = 82840
EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256 = "e1b1e315abe52e6cd31736c89d292ccd4a1a9c7370de9b1568f4a0ee72c71925"

EXPECTED_CANDIDATES = (
    "dummy_prior",
    "hist_gradient_boosting",
    "logistic_regression",
    "random_forest_compact",
)

EXPECTED_FEATURE_ROW_FIELDS = {
    "sample_id", "partition", "label", "feature_vector",
    "collection_incomplete", "dropped_events", "delivery_errors",
    "history_truncated",
}
EXPECTED_SCORE_ROW_FIELDS = {
    "sample_id", "candidate_id", "phishing_probability",
}


class StageCSelectionEvaluationAuthorizationError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hash_without(value: Mapping[str, Any], field: str) -> str:
    copy = dict(value)
    copy.pop(field, None)
    return canonical_hash(copy)


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise StageCSelectionEvaluationAuthorizationError(
            f"required JSON file not found: {path}"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageCSelectionEvaluationAuthorizationError(
            f"cannot read JSON {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise StageCSelectionEvaluationAuthorizationError(
            f"JSON root must be object: {path}"
        )
    return value


def frozen_write_json(path: Path, value: Mapping[str, Any]) -> str:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise StageCSelectionEvaluationAuthorizationError(
                f"refusing to replace non-identical frozen Task-15 output: {path}"
            )
        return "EXISTING_MATCH"
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with tmp.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return "CREATED"


def validate_task14_manifest(
    manifest: Mapping[str, Any],
    *,
    score_dataset_path: Path,
) -> dict[str, Any]:
    expected = {
        "schema_version": "stage-c-selection-score-generation-1",
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "candidate_training_complete": True,
        "model_scoring_authorized": True,
        "model_scoring_performed": True,
        "selection_feature_scoring_complete": True,
        "selection_label_access_authorized": False,
        "selection_labels_accessed": False,
        "selection_metrics_computed": False,
        "model_selection_authorized": False,
        "candidate_selected": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "final_holdout_touched": False,
        "authorization_sha256": EXPECTED_TASK13_AUTHORIZATION_SHA256,
        "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
        "selection_sample_count": EXPECTED_SELECTION_COUNT,
        "selection_sample_set_sha256": EXPECTED_SELECTION_SAMPLE_SET_SHA256,
        "selection_feature_matrix_sha256": EXPECTED_SELECTION_FEATURE_MATRIX_SHA256,
        "candidate_count": EXPECTED_CANDIDATE_COUNT,
        "candidate_artifact_set_sha256": EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
        "score_row_count": EXPECTED_SCORE_ROWS,
        "score_dataset_sha256": EXPECTED_TASK14_SCORE_DATASET_SHA256,
        "score_schema": ["sample_id", "candidate_id", "phishing_probability"],
        "score_order": "SAMPLE_ID_ASCENDING_THEN_CANDIDATE_ID_ASCENDING",
        "scoring_manifest_sha256": EXPECTED_TASK14_SCORING_MANIFEST_SHA256,
        "next_gate": (
            "ISSUE_STAGE_C_SELECTION_LABEL_EVALUATION_AUTHORIZATION_FOR_FROZEN_SCORES"
        ),
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise StageCSelectionEvaluationAuthorizationError(
                f"Task-14 scoring manifest guard mismatch: {key}"
            )
    if (
        hash_without(manifest, "scoring_manifest_sha256")
        != EXPECTED_TASK14_SCORING_MANIFEST_SHA256
    ):
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-14 canonical scoring manifest hash mismatch"
        )
    if sha256_file(score_dataset_path) != EXPECTED_TASK14_SCORE_DATASET_SHA256:
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-14 score dataset SHA-256 mismatch"
        )

    git = manifest.get("git_provenance")
    candidate_scores = manifest.get("candidate_scores")
    prohibitions = manifest.get("prohibitions_preserved")
    if not isinstance(git, Mapping):
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-14 Git provenance missing"
        )
    if git.get("git_head") != EXPECTED_TASK14_GIT_HEAD:
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-14 Git identity changed"
        )
    if not isinstance(candidate_scores, list):
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-14 candidate score identities missing"
        )
    if not isinstance(prohibitions, Mapping) or not all(
        prohibitions.get(key) is True
        for key in (
            "selection_label_read",
            "selection_metric_computation",
            "candidate_ranking",
            "candidate_choice",
            "model_refit",
            "calibration_access",
            "threshold_selection",
            "deployment",
            "final_holdout_access",
        )
    ):
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-14 prohibitions changed"
        )

    by_id: dict[str, dict[str, Any]] = {}
    for row in candidate_scores:
        if not isinstance(row, Mapping):
            raise StageCSelectionEvaluationAuthorizationError(
                "Task-14 candidate score record invalid"
            )
        cid = row.get("candidate_id")
        count = row.get("score_count")
        score_sha = row.get("score_vector_sha256")
        artifact_sha = row.get("artifact_sha256")
        if cid not in EXPECTED_CANDIDATES or cid in by_id:
            raise StageCSelectionEvaluationAuthorizationError(
                "Task-14 candidate score identity invalid"
            )
        if count != EXPECTED_SELECTION_COUNT:
            raise StageCSelectionEvaluationAuthorizationError(
                f"Task-14 candidate score count changed: {cid}"
            )
        if not isinstance(score_sha, str) or len(score_sha) != 64:
            raise StageCSelectionEvaluationAuthorizationError(
                f"Task-14 candidate score hash invalid: {cid}"
            )
        if not isinstance(artifact_sha, str) or len(artifact_sha) != 64:
            raise StageCSelectionEvaluationAuthorizationError(
                f"Task-14 artifact hash invalid: {cid}"
            )
        by_id[cid] = {
            "candidate_id": cid,
            "family": row.get("family"),
            "eligible_for_later_selection": row.get(
                "eligible_for_later_selection"
            ),
            "artifact_sha256": artifact_sha,
            "score_count": count,
            "score_vector_sha256": score_sha,
        }
    if tuple(sorted(by_id)) != EXPECTED_CANDIDATES:
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-14 candidate score set changed"
        )
    return by_id


def scan_score_dataset(
    score_dataset_path: Path,
    expected_candidate_scores: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    rows_by_candidate: dict[str, list[dict[str, Any]]] = {
        cid: [] for cid in EXPECTED_CANDIDATES
    }
    sample_to_candidates: dict[str, set[str]] = defaultdict(set)
    observed_order: list[tuple[str, str]] = []
    row_count = 0

    with score_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCSelectionEvaluationAuthorizationError(
                    f"invalid score JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_SCORE_ROW_FIELDS:
                raise StageCSelectionEvaluationAuthorizationError(
                    "score row closed-schema mismatch"
                )
            sid = row["sample_id"]
            cid = row["candidate_id"]
            score = row["phishing_probability"]
            if not isinstance(sid, str) or not sid:
                raise StageCSelectionEvaluationAuthorizationError(
                    "score sample_id invalid"
                )
            if cid not in EXPECTED_CANDIDATES:
                raise StageCSelectionEvaluationAuthorizationError(
                    "score candidate_id invalid"
                )
            if type(score) not in (int, float) or not math.isfinite(score):
                raise StageCSelectionEvaluationAuthorizationError(
                    "score probability invalid"
                )
            score = float(score)
            if score < 0.0 or score > 1.0:
                raise StageCSelectionEvaluationAuthorizationError(
                    "score probability outside [0,1]"
                )
            if cid in sample_to_candidates[sid]:
                raise StageCSelectionEvaluationAuthorizationError(
                    "duplicate sample/candidate score row"
                )
            sample_to_candidates[sid].add(cid)
            observed_order.append((sid, cid))
            rows_by_candidate[cid].append({
                "sample_id": sid,
                "phishing_probability": score,
            })
            row_count += 1

    if row_count != EXPECTED_SCORE_ROWS:
        raise StageCSelectionEvaluationAuthorizationError(
            "score row count changed"
        )
    if len(sample_to_candidates) != EXPECTED_SELECTION_COUNT:
        raise StageCSelectionEvaluationAuthorizationError(
            "score sample count changed"
        )
    expected_candidate_set = set(EXPECTED_CANDIDATES)
    if any(cids != expected_candidate_set for cids in sample_to_candidates.values()):
        raise StageCSelectionEvaluationAuthorizationError(
            "score sample candidate coverage changed"
        )

    sample_ids = sorted(sample_to_candidates)
    if canonical_hash(sample_ids) != EXPECTED_SELECTION_SAMPLE_SET_SHA256:
        raise StageCSelectionEvaluationAuthorizationError(
            "score sample-set identity changed"
        )
    expected_order = [
        (sid, cid)
        for sid in sample_ids
        for cid in EXPECTED_CANDIDATES
    ]
    if observed_order != expected_order:
        raise StageCSelectionEvaluationAuthorizationError(
            "score dataset order changed"
        )

    verified_candidate_scores: dict[str, str] = {}
    for cid in EXPECTED_CANDIDATES:
        rows = rows_by_candidate[cid]
        expected = expected_candidate_scores[cid]["score_vector_sha256"]
        actual = canonical_hash(rows)
        if actual != expected:
            raise StageCSelectionEvaluationAuthorizationError(
                f"candidate score-vector identity changed: {cid}"
            )
        verified_candidate_scores[cid] = actual

    return {
        "score_row_count": row_count,
        "selection_sample_count": len(sample_ids),
        "selection_sample_set_sha256": EXPECTED_SELECTION_SAMPLE_SET_SHA256,
        "candidate_score_vector_sha256": verified_candidate_scores,
        "score_order": "SAMPLE_ID_ASCENDING_THEN_CANDIDATE_ID_ASCENDING",
        "sample_ids": sample_ids,
        "rows_by_candidate": rows_by_candidate,
    }


def derive_selection_labels(
    feature_dataset_path: Path,
    *,
    expected_sample_ids: list[str],
) -> dict[str, Any]:
    if sha256_file(feature_dataset_path) != EXPECTED_FEATURE_DATASET_SHA256:
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-10 feature dataset SHA-256 mismatch"
        )

    expected_id_set = set(expected_sample_ids)
    seen_all: set[str] = set()
    labels: list[dict[str, Any]] = []

    with feature_dataset_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise StageCSelectionEvaluationAuthorizationError(
                    f"invalid feature JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, Mapping) or set(row) != EXPECTED_FEATURE_ROW_FIELDS:
                raise StageCSelectionEvaluationAuthorizationError(
                    "feature row closed-schema mismatch"
                )
            sid = row["sample_id"]
            part = row["partition"]
            label = row["label"]
            incomplete = row["collection_incomplete"]
            if not isinstance(sid, str) or not sid or sid in seen_all:
                raise StageCSelectionEvaluationAuthorizationError(
                    "duplicate/invalid feature sample_id"
                )
            if part not in {"train", "selection", "calibration"}:
                raise StageCSelectionEvaluationAuthorizationError(
                    "feature partition invalid"
                )
            if label not in (0, 1):
                raise StageCSelectionEvaluationAuthorizationError(
                    "feature label invalid"
                )
            if type(incomplete) is not bool:
                raise StageCSelectionEvaluationAuthorizationError(
                    "feature collection flag invalid"
                )
            seen_all.add(sid)

            if sid in expected_id_set:
                if part != "selection" or incomplete:
                    raise StageCSelectionEvaluationAuthorizationError(
                        "authorized selection sample changed partition/completeness"
                    )
                labels.append({"sample_id": sid, "label": int(label)})

    if len(seen_all) != EXPECTED_TOTAL_ROWS:
        raise StageCSelectionEvaluationAuthorizationError(
            "full feature row count changed"
        )

    labels.sort(key=lambda x: x["sample_id"])
    if [row["sample_id"] for row in labels] != expected_sample_ids:
        raise StageCSelectionEvaluationAuthorizationError(
            "selection label sample coverage changed"
        )

    counts = Counter(row["label"] for row in labels)
    label_counts = {"legitimate": counts[0], "phishing": counts[1]}
    if label_counts != EXPECTED_SELECTION_LABEL_COUNTS:
        raise StageCSelectionEvaluationAuthorizationError(
            "selection label counts changed"
        )
    return {
        "selection_label_count": len(labels),
        "selection_label_counts": label_counts,
        "selection_label_vector_sha256": canonical_hash(labels),
        "labels": labels,
    }


def build_evaluation_input_identity(
    *,
    labels: list[Mapping[str, Any]],
    rows_by_candidate: Mapping[str, list[Mapping[str, Any]]],
) -> str:
    label_by_id = {
        str(row["sample_id"]): int(row["label"])
        for row in labels
    }
    joined: list[dict[str, Any]] = []
    for cid in EXPECTED_CANDIDATES:
        for row in rows_by_candidate[cid]:
            sid = str(row["sample_id"])
            if sid not in label_by_id:
                raise StageCSelectionEvaluationAuthorizationError(
                    "score/label join coverage mismatch"
                )
            joined.append({
                "sample_id": sid,
                "candidate_id": cid,
                "label": label_by_id[sid],
                "phishing_probability": float(row["phishing_probability"]),
            })
    joined.sort(key=lambda x: (x["sample_id"], x["candidate_id"]))
    if len(joined) != EXPECTED_SCORE_ROWS:
        raise StageCSelectionEvaluationAuthorizationError(
            "evaluation join row count changed"
        )
    return canonical_hash(joined)


def validate_experiment_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    if contract.get("schema_version") != "stage-c-experiment-contract-1":
        raise StageCSelectionEvaluationAuthorizationError(
            "experiment contract schema changed"
        )
    if contract.get("stage") != "C" or contract.get("protocol_id") != "low-fpr-generalization-v1":
        raise StageCSelectionEvaluationAuthorizationError(
            "experiment contract identity changed"
        )
    if contract.get("research_only") is not True or contract.get("deployment_authorized") is not False:
        raise StageCSelectionEvaluationAuthorizationError(
            "experiment contract safety state changed"
        )
    objective = contract.get("objective")
    holdout = contract.get("holdout_contract")
    development = contract.get("development_contract")
    if not all(isinstance(x, Mapping) for x in (objective, holdout, development)):
        raise StageCSelectionEvaluationAuthorizationError(
            "experiment contract sections missing"
        )
    guards = [
        (objective.get("primary_metric") == "false_positive_rate", "primary metric"),
        (objective.get("primary_fpr_cap") == 0.01, "primary FPR cap"),
        (objective.get("confidence_level") == 0.95, "confidence level"),
        (objective.get("require_observed_fpr_at_or_below_cap") is True, "observed FPR guard"),
        (objective.get("require_wilson_upper_at_or_below_cap") is True, "Wilson guard"),
        (objective.get("secondary_metric") == "recall", "secondary metric"),
        (holdout.get("selection_use_prohibited") is True, "holdout selection prohibition"),
        (holdout.get("calibration_use_prohibited") is True, "holdout calibration prohibition"),
        (holdout.get("threshold_selection_use_prohibited") is True, "holdout threshold prohibition"),
        (development.get("test_locked_until_candidate_and_threshold_frozen") is True, "test lock"),
    ]
    for ok, name in guards:
        if not ok:
            raise StageCSelectionEvaluationAuthorizationError(
                f"experiment contract changed: {name}"
            )
    return {
        "experiment_contract_sha256": canonical_hash(contract),
        "primary_metric": "false_positive_rate",
        "primary_fpr_cap": 0.01,
        "confidence_level": 0.95,
        "require_observed_fpr_at_or_below_cap": True,
        "require_wilson_upper_at_or_below_cap": True,
        "secondary_metric": "recall",
    }


def _git_provenance(repo_root: Path) -> dict[str, str]:
    paths = [
        "ml/evaluation/stage_c_selection_label_evaluation_authorization.py",
        "ml/evaluation/authorize_stage_c_selection_label_evaluation.py",
        "ml/evaluation/stage_c_selection_score_generation.py",
        "ml/evaluation/stage_c_selection_scoring_authorization.py",
        "ml/data/manifests/stage-c-experiment-contract-v1.json",
    ]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        ).stdout.strip()
        if len(head) != 40:
            raise StageCSelectionEvaluationAuthorizationError(
                "invalid Git HEAD identity"
            )
        for relative in paths:
            subprocess.run(
                ["git", "cat-file", "-e", f"HEAD:{relative}"],
                cwd=repo_root,
                capture_output=True,
                check=True,
            )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *paths],
            cwd=repo_root,
        ).returncode
    except (OSError, subprocess.CalledProcessError) as exc:
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-15 and bound evaluation files must be committed before authorization"
        ) from exc
    if dirty != 0:
        raise StageCSelectionEvaluationAuthorizationError(
            "Task-15/bound evaluation files differ from committed HEAD"
        )
    return {
        "git_head": head,
        "task15_module_sha256": sha256_file(repo_root / paths[0]),
        "task15_cli_sha256": sha256_file(repo_root / paths[1]),
        "task14_module_sha256": sha256_file(repo_root / paths[2]),
        "task13_module_sha256": sha256_file(repo_root / paths[3]),
        "experiment_contract_file_sha256": sha256_file(repo_root / paths[4]),
    }


def issue_selection_label_evaluation_authorization(
    *,
    repo_root: Path,
    feature_dataset_path: Path,
    score_dataset_path: Path,
    score_manifest_path: Path,
    experiment_contract_path: Path,
) -> dict[str, Any]:
    manifest = load_json(score_manifest_path)
    experiment = load_json(experiment_contract_path)

    expected_scores = validate_task14_manifest(
        manifest,
        score_dataset_path=score_dataset_path,
    )
    score_scope = scan_score_dataset(
        score_dataset_path,
        expected_candidate_scores=expected_scores,
    )
    label_scope = derive_selection_labels(
        feature_dataset_path,
        expected_sample_ids=score_scope["sample_ids"],
    )
    evaluation_input_sha = build_evaluation_input_identity(
        labels=label_scope["labels"],
        rows_by_candidate=score_scope["rows_by_candidate"],
    )
    experiment_binding = validate_experiment_contract(experiment)
    git = _git_provenance(repo_root)

    authorization = {
        "schema_version": AUTH_SCHEMA,
        "status": "PASS",
        "stage": "C",
        "protocol_id": "low-fpr-generalization-v1",
        "research_only": True,
        "deployment_authorized": False,
        "model_training_authorized": True,
        "model_scoring_authorized": True,
        "selection_feature_scoring_complete": True,
        "selection_label_access_authorized": True,
        "selection_label_verification_performed": True,
        "selection_metric_computation_authorized": True,
        "selection_metrics_computed": False,
        "model_selection_authorized": False,
        "candidate_selected": False,
        "calibration_fitting_authorized": False,
        "threshold_selection_authorized": False,
        "final_holdout_touched": False,
        "authorized_action": (
            "EVALUATE_FROZEN_SELECTION_SCORES_AGAINST_FROZEN_SELECTION_LABELS"
        ),
        "evaluation_scope": {
            "selection_sample_count": EXPECTED_SELECTION_COUNT,
            "selection_sample_set_sha256": EXPECTED_SELECTION_SAMPLE_SET_SHA256,
            "selection_label_counts": label_scope["selection_label_counts"],
            "selection_label_vector_sha256": label_scope[
                "selection_label_vector_sha256"
            ],
            "score_row_count": EXPECTED_SCORE_ROWS,
            "score_dataset_sha256": EXPECTED_TASK14_SCORE_DATASET_SHA256,
            "candidate_count": EXPECTED_CANDIDATE_COUNT,
            "candidate_artifact_set_sha256": EXPECTED_CANDIDATE_ARTIFACT_SET_SHA256,
            "candidate_score_vector_sha256": score_scope[
                "candidate_score_vector_sha256"
            ],
            "evaluation_input_sha256": evaluation_input_sha,
            "join_key": "sample_id",
            "label_field": "label",
            "score_field": "phishing_probability",
        },
        "authorized_metrics": {
            "average_precision": True,
            "roc_auc": True,
            "brier_score": True,
            "log_loss": True,
            "low_fpr_threshold_sweep_for_diagnostics": True,
            "observed_fpr": True,
            "wilson_upper_95": True,
            "recall": True,
            "primary_fpr_cap": experiment_binding["primary_fpr_cap"],
            "threshold_freeze_authorized": False,
        },
        "experiment_constraints": experiment_binding,
        "identity_bindings": {
            "task13_authorization_sha256": EXPECTED_TASK13_AUTHORIZATION_SHA256,
            "task14_score_dataset_sha256": EXPECTED_TASK14_SCORE_DATASET_SHA256,
            "task14_scoring_manifest_sha256": EXPECTED_TASK14_SCORING_MANIFEST_SHA256,
            "feature_dataset_sha256": EXPECTED_FEATURE_DATASET_SHA256,
            **git,
        },
        "prohibitions": {
            "model_refit": True,
            "candidate_ranking": True,
            "candidate_choice": True,
            "model_selection": True,
            "calibration_access": True,
            "calibration_fitting": True,
            "threshold_freeze": True,
            "deployment": True,
            "final_holdout_access": True,
        },
        "next_gate": (
            "EVALUATE_STAGE_C_FROZEN_SELECTION_SCORES_WITHOUT_MODEL_SELECTION"
        ),
    }
    authorization["authorization_sha256"] = canonical_hash(authorization)
    return authorization
