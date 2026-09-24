"""
CAPSTONE-1 Generalization Evaluation Suite
Evaluates trained models across 4 distinct evaluation regimes:
 1. In-Distribution Standard Test Split
 2. Temporal Split (future collection window)
 3. Unseen-Domain Split (zero domain overlap with training)
 4. Adversarial & Counterfactual Split
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import itertools
import json
import math
import platform
import re
import sys
import warnings
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, average_precision_score
from sklearn.exceptions import ConvergenceWarning
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

SPLITS_DIR = Path(__file__).resolve().parent / "splits"
GENERALIZATION_REPORT_JSON = Path(__file__).resolve().parent / "generalization_eval_report.json"

FEATURES = [
    "url_length", "hostname_length", "path_length", "subdomain_count", "entropy",
    "ip_address_host", "domain_length", "domain_is_ip", "dom_element_count",
    "form_count", "input_count", "login_form_detected", "password_field_detected",
    "otp_field_detected", "cross_origin_submission", "form_secure_transport",
    "redirect_count", "cross_domain_redirect", "credential_requested",
    "password_requested", "otp_requested", "purpose_mismatch", "brand_impersonation_indicator"
]


def load_split(name: str):
    df = pd.read_csv(SPLITS_DIR / f"{name}_split.csv")
    X = df[FEATURES].astype(float).values
    y = (df["ground_truth"] == "phishing").astype(int).values
    return X, y, df


def run_generalization():
    X_train, y_train, _ = load_split("train")

    models = {
        "Logistic_Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random_Forest": RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42),
        "Gradient_Boosting": GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42),
    }

    # Train all models on base training split
    for model in models.values():
        model.fit(X_train, y_train)

    evaluation_splits = ["test", "temporal", "unseen_domain", "adversarial"]
    report = {}

    print("================================================================================")
    print("CAPSTONE-1 GENERALIZATION EXPERIMENTS ACROSS 4 EVALUATION REGIMES")
    print("================================================================================")

    for split_name in evaluation_splits:
        report[split_name] = {}
        X_eval, y_eval, df_eval = load_split(split_name)

        print(f"\n--- Split: [{split_name.upper()}] ({len(y_eval)} samples) ---")
        for model_name, model in models.items():
            y_pred = model.predict(X_eval)
            acc = accuracy_score(y_eval, y_pred)
            prec = precision_score(y_eval, y_pred, zero_division=0)
            rec = recall_score(y_eval, y_pred, zero_division=0)
            f1 = f1_score(y_eval, y_pred, zero_division=0)

            cm = confusion_matrix(y_eval, y_pred, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

            res = {
                "sample_count": len(y_eval),
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1_score": round(float(f1), 4),
                "fpr": round(float(fpr), 4),
                "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            }
            report[split_name][model_name] = res
            print(f"  {model_name:20s} | Acc: {acc:.2f} | Prec: {prec:.2f} | Rec: {rec:.2f} | F1: {f1:.2f} | FPR: {fpr:.2f}")

    with open(GENERALIZATION_REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n================================================================================")
    print(f"Generalization Report saved to {GENERALIZATION_REPORT_JSON}")
    print("================================================================================")


PILOT_SEED = 20260908
PILOT_REPRESENTATIONS = ("B0", "B1", "B2", "G", "P")
PILOT_FAMILIES = tuple(f"F{i}" for i in range(1, 7))
PILOT_LIMIT = (
    "Exploratory controlled browser fixtures only: six authored scenario groups, "
    "not independently sourced real-world samples. Full RQ1, generalization, "
    "operational FPR, prevention timing, and CGE benefit remain unresolved. "
    "Graph/direct-event parity cannot establish that a graph is necessary."
)


def require(condition, message):
    """Input checks remain active under python -O."""
    if not condition:
        raise ValueError(message)


def compact_hash(value):
    # Event fields are integers, finite confidence values, strings, and nulls;
    # preserve input key order to match the collector's JSON.stringify hash.
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def pilot_key(row):
    return tuple(row.get(key) for key in ("family", "label", "layout", "repeat"))


def validate_pilot(data):
    """Reject incomplete, contaminated, or inconsistent exports before fitting."""
    require(isinstance(data, dict) and data.get("status") == "PASS", "Collection status must be PASS")
    require(data.get("protocol_version") == "controlled-1", "Unsupported controlled protocol")
    require(data.get("failures") == [], "Collection contains failed attempts; do not score an incomplete protocol")
    manifest = data.get("manifest", {})
    require(manifest.get("seed") == PILOT_SEED, "Unexpected protocol seed")
    expected = set(itertools.product(PILOT_FAMILIES, (0, 1), range(1, 5), range(1, 4)))
    for name, rows in (("manifest", manifest.get("episodes")), ("episodes", data.get("episodes"))):
        require(isinstance(rows, list) and len(rows) == 144, f"{name} must contain exactly 144 episodes")
        require(all(isinstance(row, dict) for row in rows), f"Invalid {name} rows")
        require(all(type(row.get(key)) is int for row in rows for key in ("label", "layout", "repeat")), "Labels/layouts/repeats must be integers")
        require({pilot_key(row) for row in rows} == expected, f"{name} has missing or duplicate family/case/layout/repeat combinations")
        require(all(isinstance(row.get("episode_id"), str) and row["episode_id"] for row in rows), "Missing episode identity")
        require(len({row["episode_id"] for row in rows}) == 144, "Duplicate episode identity")
    manifest_rows = {row["episode_id"]: pilot_key(row) for row in manifest["episodes"]}
    require({row["episode_id"]: pilot_key(row) for row in data["episodes"]} == manifest_rows, "Episode labels/groups disagree with frozen manifest")

    schemas = manifest.get("feature_schemas")
    require(isinstance(schemas, dict) and set(schemas) == set(PILOT_REPRESENTATIONS), "Frozen feature_schemas required for B0/B1/B2/G/P")
    forbidden = re.compile(r"(^|[_.:])(label|family|fixture|seed|repeat|layout|hostname|filename|episode_id|session_id|tab_id|field_id|form_id|timestamp_ms|received_ms|authorization|forwarding)($|[_.:])", re.I)
    for name, columns in schemas.items():
        require(isinstance(columns, list) and columns and all(isinstance(k, str) for k in columns), f"Invalid {name} feature schema")
        require(len(set(columns)) == len(columns), f"Duplicate {name} feature column")
        require(all(not forbidden.search(k) and not re.search(r"https?://|[\\/]|^[Ff][1-6]$", k) for k in columns), f"Forbidden identifier/label feature in {name}")
    require(schemas["G"] == schemas["P"], "Graph and direct-event schemas must match exactly")
    hashes = data.get("source_hashes")
    require(isinstance(hashes, dict) and hashes and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in hashes.values()), "Source SHA256 hashes are required")

    # Reuse the existing strict sanitized-event boundary, without importing DB/server modules.
    root = str(Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)
    from backend.events import SanitizedEvent

    sessions, event_hashes = set(), set()
    for episode in data["episodes"]:
        eid = episode["episode_id"]
        for flag in ("valid", "privacy_canary_absent", "database_match"):
            require(episode.get(flag) is True, f"{eid}: {flag} must pass")
        for counter in ("dropped", "content_dropped", "pending"):
            require(type(episode.get(counter)) is int and episode[counter] == 0, f"{eid}: nonzero or missing {counter}")
        for stamp in ("cutoff_ms", "last_action_ms", "exported_ms"):
            require(type(episode.get(stamp)) is int and episode[stamp] >= 0, f"{eid}: invalid {stamp}")
        duration = episode.get("action_duration_ms")
        require(type(duration) in (int, float) and math.isfinite(duration) and 0 <= duration <= 2000, f"{eid}: action duration outside 0..2000 ms")
        require(episode["cutoff_ms"] - episode["last_action_ms"] == 3000, f"{eid}: incorrect observation horizon")
        require(episode["exported_ms"] >= episode["cutoff_ms"], f"{eid}: export precedes cutoff")
        events = episode.get("events")
        require(isinstance(events, list) and 0 < len(events) < 2000, f"{eid}: empty or potentially truncated retained events")
        require(compact_hash(events) == episode.get("events_sha256"), f"{eid}: immutable event hash mismatch")
        require(episode["events_sha256"] not in event_hashes, f"{eid}: duplicate event export")
        event_hashes.add(episode["events_sha256"])
        require(isinstance(episode.get("session_id"), str) and episode["session_id"] not in sessions, f"{eid}: session reused across episodes")
        sessions.add(episode["session_id"])
        for event in events:
            SanitizedEvent.model_validate(event)
            require(event["session_id"] == episode["session_id"], f"{eid}: mixed session events")
            require(event["received_ms"] <= episode["cutoff_ms"], f"{eid}: event received after horizon")
        require(len({event["tab_id"] for event in events}) == 1, f"{eid}: mixed tab events")
        require([e["event_seq"] for e in events] == list(range(1, len(events) + 1)), f"{eid}: missing, duplicated, or reordered event sequence")
        require(all(a["received_ms"] <= b["received_ms"] for a, b in zip(events, events[1:])), f"{eid}: recorder clock reversal")
        reps = episode.get("representations")
        require(isinstance(reps, dict) and set(reps) == set(PILOT_REPRESENTATIONS), f"{eid}: missing representation")
        for name in PILOT_REPRESENTATIONS:
            require(isinstance(reps[name], dict) and set(reps[name]) == set(schemas[name]), f"{eid}: {name} schema drift")
            require(all(type(v) in (int, float) and math.isfinite(v) for v in reps[name].values()), f"{eid}: nonfinite/nonnumeric feature")
        require(reps["G"] == reps["P"], f"{eid}: graph/direct feature parity failed")
        if "event_count" in reps["B0"]:
            require(reps["B0"]["event_count"] == len(events), f"{eid}: flat event count disagrees with shared observations")
        for field in ("graph_size", "timings_ms"):
            require(isinstance(episode.get(field), dict) and episode[field], f"{eid}: missing {field}")
            require(all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in episode[field].values()), f"{eid}: invalid {field}")
        require(set(episode["graph_size"]) == {"nodes", "edges"}, f"{eid}: invalid graph size keys")
    return schemas


def pilot_metrics(labels, scores):
    labels, scores = np.asarray(labels), np.asarray(scores, dtype=float)
    require(len(labels) == len(scores) and len(labels) > 0, "Empty or mismatched metric inputs")
    require(set(labels.tolist()) <= {0, 1} and np.isfinite(scores).all() and ((0 <= scores) & (scores <= 1)).all(), "Invalid labels or probability scores")
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(labels, scores >= 0.5, labels=[0, 1]).ravel())
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    return {
        "case_layout_count": len(labels), "positive_count": tp + fn, "negative_count": tn + fp,
        "prevalence": float(np.mean(labels)),
        "AP": float(average_precision_score(labels, scores)) if tp + fn else None,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "F1": ratio(2 * tp, 2 * tp + fp + fn), "FPR": ratio(fp, fp + tn),
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "denominators": {"precision": tp + fp, "recall": tp + fn, "F1": 2 * tp + fp + fn, "FPR": fp + tn},
        "threshold": 0.5,
    }


def pilot_folds(episodes):
    groups = np.array([row["family"] for row in episodes])
    visited = np.zeros(len(episodes), dtype=int)
    folds = []
    for train, test in LeaveOneGroupOut().split(np.zeros((len(episodes), 1)), groups=groups):
        require(len(train) == 120 and len(test) == 24, "Incorrect grouped fold sizes")
        require(not set(groups[train]) & set(groups[test]), "Family leakage across fold")
        require(len(set(groups[test])) == 1, "A fold must hold out one complete family")
        visited[test] += 1
        folds.append((str(groups[test[0]]), train, test))
    require(len(folds) == 6 and (visited == 1).all(), "Every episode must have exactly one held-out prediction")
    return folds


def paired_family_bootstrap(aggregated, draws=4000):
    families = np.array([row["family"] for row in aggregated])
    labels = np.array([row["label"] for row in aggregated])
    g = np.array([row["scores"]["G"] for row in aggregated])
    b2 = np.array([row["scores"]["B2"] for row in aggregated])
    grouped = [np.flatnonzero(families == family) for family in PILOT_FAMILIES]
    require(all(len(idx) == 8 and set(labels[idx]) == {0, 1} for idx in grouped), "Bootstrap requires complete paired family groups")
    rng = np.random.default_rng(PILOT_SEED)
    deltas = []
    for selection in rng.integers(0, 6, size=(draws, 6)):
        idx = np.concatenate([grouped[i] for i in selection])
        deltas.append(float(average_precision_score(labels[idx], g[idx]) - average_precision_score(labels[idx], b2[idx])))
    return {"method": "paired family percentile bootstrap", "resamples": draws, "seed": PILOT_SEED,
            "interval_95": np.percentile(deltas, [2.5, 97.5]).tolist(),
            "source_group_count": 6, "p_value": None,
            "limitation": "Conditional exploratory interval with six authored groups; nominal coverage is unestablished, not confirmatory significance."}


def evaluate_pilot(data, bootstrap_draws=4000):
    schemas = validate_pilot(data)
    episodes = sorted(data["episodes"], key=pilot_key)
    event_hashes_before = [compact_hash(row["events"]) for row in episodes]
    labels = np.array([row["label"] for row in episodes])
    matrices = {name: np.array([[row["representations"][name][k] for k in schemas[name]] for row in episodes], dtype=float) for name in PILOT_REPRESENTATIONS}
    predictions = {name: np.full(144, np.nan) for name in PILOT_REPRESENTATIONS}
    folds, equivalent = [], []
    for family, train, test in pilot_folds(episodes):
        fit = {"held_out_family": family, "train_families": sorted({episodes[i]["family"] for i in train}),
               "train_episode_ids": [episodes[i]["episode_id"] for i in train],
               "test_episode_ids": [episodes[i]["episode_id"] for i in test], "model_iterations": {}}
        for name in PILOT_REPRESENTATIONS:
            model = make_pipeline(StandardScaler(), LogisticRegression(C=1.0, solver="lbfgs", max_iter=2000, random_state=PILOT_SEED))
            with warnings.catch_warnings():
                warnings.simplefilter("error", ConvergenceWarning)
                model.fit(matrices[name][train], labels[train], logisticregression__sample_weight=np.full(len(train), 1 / 3))
            predictions[name][test] = model.predict_proba(matrices[name][test])[:, 1]
            fit["model_iterations"][name] = model[-1].n_iter_.tolist()
            buckets = defaultdict(list)
            for i in test:
                buckets[tuple(matrices[name][i])].append(int(i))
            for members in buckets.values():
                if len(set(labels[members])) < 2:
                    continue
                values = predictions[name][members]
                require(np.allclose(values, values[0], rtol=0, atol=1e-12), "Equivalent contradictory-label vectors received different same-fold scores")
                equivalent.append({"family": family, "representation": name,
                                   "episode_ids": [episodes[i]["episode_id"] for i in members],
                                   "score": float(values[0]), "opposing_label_pair_count": int(sum(labels[members]) * (len(members) - sum(labels[members])))})
        folds.append(fit)
    require(all(np.isfinite(values).all() for values in predictions.values()), "Missing or nonfinite held-out predictions")
    require(np.allclose(predictions["G"], predictions["P"], rtol=0, atol=1e-12), "Graph/direct prediction parity failed")
    require(event_hashes_before == [compact_hash(row["events"]) for row in episodes], "Feature evaluation modified observations")
    grouped = defaultdict(list)
    for i, episode in enumerate(episodes):
        grouped[pilot_key(episode)[:3]].append(i)
    aggregated = []
    for (family, label, layout), members in sorted(grouped.items()):
        require(len(members) == 3 and {episodes[i]["repeat"] for i in members} == {1, 2, 3}, "Incomplete repeat aggregation")
        aggregated.append({"family": family, "label": label, "layout": layout,
                           "episode_ids": [episodes[i]["episode_id"] for i in members],
                           "scores": {name: float(np.mean(predictions[name][members])) for name in PILOT_REPRESENTATIONS},
                           "repeat_variability": {name: {"std_population": float(np.std(predictions[name][members])),
                                                         "range": float(np.ptp(predictions[name][members]))} for name in PILOT_REPRESENTATIONS}})
    require(len(aggregated) == 48, "Expected 48 aggregated case/layout predictions")
    metrics = {}
    for name in PILOT_REPRESENTATIONS:
        metrics[name] = {"pooled": pilot_metrics([r["label"] for r in aggregated], [r["scores"][name] for r in aggregated]),
                         "per_family": {family: pilot_metrics([r["label"] for r in aggregated if r["family"] == family],
                                                              [r["scores"][name] for r in aggregated if r["family"] == family]) for family in PILOT_FAMILIES}}
    episode_predictions = [{"episode_id": row["episode_id"], "family": row["family"], "label": row["label"],
                            "layout": row["layout"], "repeat": row["repeat"], "events_sha256": row["events_sha256"],
                            "event_count": len(row["events"]), "unknown_document_events": sum(e["document_id"] is None for e in row["events"]),
                            "graph_size": row["graph_size"], "timings_ms": row["timings_ms"],
                            "scores": {name: float(predictions[name][i]) for name in PILOT_REPRESENTATIONS}}
                           for i, row in enumerate(episodes)]
    return {"status": "COMPLETED_CONTROLLED_PILOT", "protocol_version": data["protocol_version"],
            "created_at": datetime.now(timezone.utc).isoformat(), "limitation": PILOT_LIMIT, "full_rq1": "UNRESOLVED",
            "episode_count": 144, "aggregated_case_layout_count": 48, "authored_family_count": 6,
            "model": {"type": "StandardScaler + LogisticRegression", "C": 1.0, "solver": "lbfgs", "max_iter": 2000,
                      "random_state": PILOT_SEED, "repeat_training_weight": 1 / 3, "threshold": 0.5, "hyperparameter_tuning": False},
            "feature_schemas": schemas, "feature_counts": {k: len(v) for k, v in schemas.items()},
            "metrics": metrics, "primary_contrast": {"name": "AP(G) - AP(B2)", "delta_AP": metrics["G"]["pooled"]["AP"] - metrics["B2"]["pooled"]["AP"],
                                                       "bootstrap": paired_family_bootstrap(aggregated, bootstrap_draws)},
            "secondary_delta_AP": {name: metrics["G"]["pooled"]["AP"] - metrics[name]["pooled"]["AP"] for name in ("B0", "B1")},
            "folds": folds, "episode_predictions": episode_predictions, "aggregated_predictions": aggregated,
            "equivalent_opposing_label_groups": equivalent, "graph_direct_feature_and_prediction_parity": True,
            "source_hashes": data["source_hashes"], "manifest": data["manifest"], "collection_failures": data["failures"],
            "collection_metadata": {key: value for key, value in data.items() if key not in {"episodes", "manifest", "failures", "source_hashes"}},
            "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "environment": {"python": platform.python_version(), "platform": platform.platform(),
                            "packages": {name: importlib.metadata.version(name) for name in ("scikit-learn", "numpy", "scipy", "pandas", "pydantic")}}}


def pilot_self_check():
    """Synthetic integrity assertions only; these are not browser detection results."""
    import copy
    import uuid
    rows = []
    for i, key in enumerate(itertools.product(PILOT_FAMILIES, (0, 1), range(1, 5), range(1, 4))):
        family, label, layout, repeat = key
        session = str(uuid.UUID(int=i + 1))
        event = {"event_type": "DOCUMENT_STARTED", "sensitive_type": None, "field_id": None, "form_id": None,
                 "frame_origin": "http://127.0.0.1", "target_origin": None, "destination_origin": None, "initiator_origin": None,
                 "request_type": None, "interaction_type": None, "timestamp_ms": 1000, "schema_version": "1.1.0",
                 "session_id": session, "tab_id": i, "document_id": f"{i:032x}", "frame_id": 0, "parent_frame_id": None,
                 "event_seq": 1, "received_ms": 1000, "trust": "ISOLATED_CONTENT_SCRIPT", "confidence": 1}
        rows.append({"episode_id": str(i), "family": family, "label": label, "layout": layout, "repeat": repeat,
                     "events": [event], "events_sha256": compact_hash([event]), "session_id": session,
                     "representations": {name: {"event_count": 1} for name in PILOT_REPRESENTATIONS},
                     "valid": True, "privacy_canary_absent": True, "database_match": True,
                     "dropped": 0, "content_dropped": 0, "pending": 0, "action_duration_ms": 10,
                     "last_action_ms": 1000, "cutoff_ms": 4000, "exported_ms": 4001,
                     "graph_size": {"nodes": 1, "edges": 0}, "timings_ms": {"G": 0.1}})
    data = {"status": "PASS", "protocol_version": "controlled-1", "failures": [], "source_hashes": {"self_check": "0" * 64},
            "manifest": {"seed": PILOT_SEED, "feature_schemas": {name: ["event_count"] for name in PILOT_REPRESENTATIONS},
                         "episodes": [{key: row[key] for key in ("episode_id", "family", "label", "layout", "repeat")} for row in rows]}, "episodes": rows}
    validate_pilot(data)
    report = evaluate_pilot(data, bootstrap_draws=16)
    assert report["metrics"]["G"]["pooled"]["AP"] == 0.5
    assert report["primary_contrast"]["bootstrap"]["interval_95"] == [0.0, 0.0]
    assert len(report["folds"]) == 6 and len(report["aggregated_predictions"]) == 48
    assert report["equivalent_opposing_label_groups"]
    assert pilot_metrics([0, 0], [0.1, 0.2])["AP"] is None
    assert pilot_metrics([0, 1], [0.1, 0.2])["precision"] is None
    assert pilot_metrics([0, 1], [0.1, 0.2])["FPR"] == 0
    assert pilot_metrics([0, 1], [0.1, 0.9])["AP"] == 1
    for change in (
        lambda d: d["episodes"].pop(),
        lambda d: d["episodes"][0].update(label=1),
        lambda d: d["episodes"][0].update(events_sha256="0" * 64),
        lambda d: d["episodes"][0].update(dropped=1),
        lambda d: d["episodes"][0].update(cutoff_ms=4001),
        lambda d: d["episodes"][0].update(action_duration_ms=2001),
        lambda d: d["episodes"][0]["representations"]["P"].update(event_count=2),
        lambda d: d["manifest"]["feature_schemas"]["B0"].append("label"),
    ):
        invalid = copy.deepcopy(data)
        change(invalid)
        try:
            validate_pilot(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Malformed pilot was not rejected")
    print(json.dumps({"self_check": "PASS", "scope": "Synthetic integrity checks only; no browser detection result"}))


def main():
    parser = argparse.ArgumentParser(description="Legacy split evaluation or the preregistered controlled browser pilot")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--controlled-pilot", type=Path, metavar="PATH")
    mode.add_argument("--self-check", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_check:
        parser.error("--output requires --controlled-pilot") if args.output else pilot_self_check()
    elif args.controlled_pilot:
        raw = args.controlled_pilot.read_bytes()
        data = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Nonfinite JSON constant: {value}")))
        report = evaluate_pilot(data)
        report["input_sha256"] = hashlib.sha256(raw).hexdigest()
        output = args.output or args.controlled_pilot.with_name(args.controlled_pilot.stem + "-evaluation.json")
        require(output.resolve() != args.controlled_pilot.resolve(), "Output must not overwrite immutable collection input")
        require(not output.exists(), "Output already exists; retain earlier evidence and choose a new output path")
        with output.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False, allow_nan=False)
            handle.write("\n")
        print(json.dumps({"status": report["status"], "report": str(output), "primary_delta_AP": report["primary_contrast"]["delta_AP"], "full_rq1": "UNRESOLVED"}))
    else:
        if args.output:
            parser.error("--output requires --controlled-pilot")
        run_generalization()


if __name__ == "__main__":
    main()
