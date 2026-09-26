from __future__ import annotations
from pathlib import Path
import ml.data.stage_c_development_feature_extraction as mod


def tiny_batch():
    return {
        "batch_id": "batch-test",
        "rows": [
            {
                "sample_id": "s1",
                "label": 1,
                "html_sha256": "a" * 64,
                "member_name": "x/1.html",
                "html_size_bytes": 12,
            }
        ],
    }


def test_state_schema_bumped_for_memory_transport():
    assert mod.STATE_SCHEMA == "stage-c-development-feature-extraction-state-2"


def test_memory_plan_contains_no_disk_html_path():
    plan = mod._memory_plan(tiny_batch(), wait_ms=250)
    assert plan["schema_version"] == "stage-c-memory-replay-plan-1"
    assert plan["items"] == [{
        "sample_id": "s1",
        "ground_truth": 1,
        "artifact_sha256": "a" * 64,
        "wait_ms": 250,
    }]
    assert "html_path" not in plan["items"][0]
    assert "html_base64" not in plan["items"][0]


def test_task10_module_has_no_raw_html_materialization():
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "def _materialize_batch(" not in source
    assert "target.write_bytes(payload)" not in source
    assert "stage-c-collect-memory-replay.mjs" in source
    assert '"raw_html_materialized_to_disk": False' in source


def test_memory_collector_declares_closed_safety_policy():
    root = Path(mod.__file__).resolve().parents[2]
    path = root / "scripts" / "stage-c-collect-memory-replay.mjs"
    source = path.read_text(encoding="utf-8")
    assert "stage-c-memory-replay-1" in source
    assert "html_base64" in source
    assert "raw_html_materialized_to_disk: false" in source
    assert "raw_html_received_via_stdin_memory_stream: true" in source
    assert "browser_response_cache_control_no_store: true" in source
    assert "readFileSync(file)" not in source


def test_memory_collector_keeps_browser_safety_barriers():
    root = Path(mod.__file__).resolve().parents[2]
    source = (root / "scripts" / "stage-c-collect-memory-replay.mjs").read_text(
        encoding="utf-8"
    )
    for required in (
        "script-src 'none'",
        "connect-src 'none'",
        "frame-src 'none'",
        "object-src 'none'",
        "form-action 'none'",
        "externalRequestsBlocked",
        "LOOPBACK_HOSTS",
        "no-store",
    ):
        assert required in source


def test_memory_transport_does_not_add_training_dependency():
    source = Path(mod.__file__).read_text(encoding="utf-8").casefold()
    assert "sklearn" not in source
    assert "predict_proba" not in source
    assert ".fit(" not in source
