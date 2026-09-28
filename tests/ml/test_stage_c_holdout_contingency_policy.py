from pathlib import Path

import pytest

import ml.data.stage_c_holdout_contingency_policy as mod
from ml.data.stage_c_holdout_contingency_policy import (
    StageCHoldoutContingencyPolicyError,
)


def test_schema_and_task25_identity_are_frozen():
    assert mod.POLICY_SCHEMA == "stage-c-final-holdout-contingency-policy-1"
    assert mod.EXPECTED_TASK25_AUTHORIZATION_SHA256 == (
        "35832fbb13ed28b93120953b8edf8dae997cb107df1116cedaeeffaf2733e59d"
    )


def test_primary_remains_compphish_v3():
    assert mod.PRIMARY["candidate_id"] == "compphish-v3-2026"
    assert mod.PRIMARY["priority"] == 1
    assert mod.PRIMARY["raw_html_expected"] is True


def test_first_fallback_is_compphish_v4():
    assert mod.FALLBACKS[0]["candidate_id"] == "compphish-v4-2026"
    assert mod.FALLBACKS[0]["priority"] == 2
    assert mod.FALLBACKS[0]["status"].startswith(
        "SAME_FAMILY_FALLBACK_REQUIRES"
    )


def test_independent_fallbacks_are_not_silently_prequalified():
    statuses = {x["candidate_id"]: x["status"] for x in mod.FALLBACKS}
    assert "REQUIRES" in statuses["phishark-2026"]
    assert "REQUIRES" in statuses["phish360"]
    assert "REQUIRES" in statuses["tr-op"]


def test_phish360_requires_temporal_review():
    row = next(x for x in mod.FALLBACKS if x["candidate_id"] == "phish360")
    assert "STRICT_FORWARD" in row["status"]


def test_phishark_access_restriction_is_recorded():
    row = next(x for x in mod.FALLBACKS if x["candidate_id"] == "phishark-2026")
    assert row["access"] == "RESTRICTED_ACADEMIC_DUA"


def test_fallback_activation_reasons_are_external_or_integrity_based():
    joined = " ".join(mod.ALLOWED_ACTIVATION_REASONS)
    assert "MODEL" not in joined
    assert "ACCURACY" not in joined
    assert "RECALL" not in joined
    assert "ACCESS_DENIED" in joined
    assert "INTEGRITY_VERIFICATION_FAILED" in joined


def test_performance_signals_are_prohibited_for_holdout_selection():
    assert "MODEL_ACCURACY" in mod.PROHIBITED_SELECTION_SIGNALS
    assert "MODEL_RECALL" in mod.PROHIBITED_SELECTION_SIGNALS
    assert "MODEL_FALSE_POSITIVE_RATE" in mod.PROHIBITED_SELECTION_SIGNALS
    assert "WHICH_HOLDOUT_MAKES_MODEL_LOOK_BEST" in mod.PROHIBITED_SELECTION_SIGNALS


def test_backup_must_pass_contamination_and_integrity_gates():
    assert "NO_OVERLAP_WITH_STAGE_C_DEVELOPMENT" in mod.REQUIRED_BACKUP_GATES
    assert (
        "NO_OVERLAP_WITH_CONSUMED_STAGE_B_FINAL_TEST"
        in mod.REQUIRED_BACKUP_GATES
    )
    assert (
        "LOCAL_ARCHIVE_SHA256_AND_SIZE_SEALED"
        in mod.REQUIRED_BACKUP_GATES
    )
    assert "CONTAMINATION_AUDIT_PASSED" in mod.REQUIRED_BACKUP_GATES


def test_task26_does_not_access_or_score_holdouts():
    src = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "urlopen(" not in src
    assert "requests.get(" not in src
    assert "predict_proba" not in src
    assert ".fit(" not in src
    assert '"final_holdout_touched": false' in src
    assert '"model_scoring_authorized": false' in src


def test_switching_after_bad_result_is_explicitly_prohibited():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert '"switch_holdout_after_bad_result": True' in src
    assert '"switch_after_evaluation_due_to_bad_model_results": False' in src


def test_frozen_write_is_immutable(tmp_path):
    path = tmp_path / "policy.json"
    assert mod.frozen_write_json(path, {"x": 1}) == "CREATED"
    assert mod.frozen_write_json(path, {"x": 1}) == "EXISTING_MATCH"
    with pytest.raises(StageCHoldoutContingencyPolicyError, match="non-identical"):
        mod.frozen_write_json(path, {"x": 2})


def test_next_gate_is_attempt_primary_or_activate_fallback():
    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert (
        "ATTEMPT_PRIMARY_FINAL_HOLDOUT_ACQUISITION_OR_ACTIVATE_"
        in src
    )
