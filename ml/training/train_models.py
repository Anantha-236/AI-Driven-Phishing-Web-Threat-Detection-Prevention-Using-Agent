"""
CAPSTONE-1 ML Model Training & Statistical Experiment Pipeline
Trains:
 - Logistic Regression (Baseline)
 - Random Forest (Ensemble)
 - XGBoost / Gradient Boosting (Gradient Boosted Decision Trees)

Evaluates across 5 Feature Subsets (A through E):
 - Subset A: URL Lexical Only
 - Subset B: URL + Domain
 - Subset C: URL + Domain + DOM Structure
 - Subset D: URL + Domain + DOM + Form Targets
 - Subset E: Full Contextual + Behavioral
"""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score

SPLITS_DIR = Path(__file__).resolve().parents[1] / "evaluation" / "splits"
MODELS_DIR = Path(__file__).resolve().parent / "artifacts"
RESULTS_JSON = Path(__file__).resolve().parent / "training_results.json"

FEATURE_GROUPS = {
    "Group_A_URL_Only": [
        "url_length", "hostname_length", "path_length", "query_length",
        "subdomain_count", "entropy", "ip_address_host", "punycode_present",
        "hyphen_count", "suspicious_token_count", "brand_keyword_count"
    ],
    "Group_B_URL_Domain": [
        "url_length", "hostname_length", "path_length", "query_length",
        "subdomain_count", "entropy", "ip_address_host", "punycode_present",
        "hyphen_count", "suspicious_token_count", "brand_keyword_count",
        "domain_length", "domain_is_ip", "domain_similarity_to_brand",
        "homograph_indicator", "domain_known_to_registry"
    ],
    "Group_C_URL_Domain_DOM": [
        "url_length", "hostname_length", "path_length", "query_length",
        "subdomain_count", "entropy", "ip_address_host", "punycode_present",
        "hyphen_count", "suspicious_token_count", "brand_keyword_count",
        "domain_length", "domain_is_ip", "domain_similarity_to_brand",
        "homograph_indicator", "domain_known_to_registry",
        "dom_element_count", "form_count", "input_count", "button_count",
        "external_script_count", "inline_script_count"
    ],
    "Group_D_URL_Domain_DOM_Form": [
        "url_length", "hostname_length", "path_length", "query_length",
        "subdomain_count", "entropy", "ip_address_host", "punycode_present",
        "hyphen_count", "suspicious_token_count", "brand_keyword_count",
        "domain_length", "domain_is_ip", "domain_similarity_to_brand",
        "homograph_indicator", "domain_known_to_registry",
        "dom_element_count", "form_count", "input_count", "button_count",
        "external_script_count", "inline_script_count",
        "login_form_detected", "password_field_detected", "otp_field_detected",
        "same_origin_submission", "cross_origin_submission", "form_secure_transport"
    ],
    "Group_E_Full_Contextual": [
        "url_length", "hostname_length", "path_length", "query_length",
        "subdomain_count", "entropy", "ip_address_host", "punycode_present",
        "hyphen_count", "suspicious_token_count", "brand_keyword_count",
        "domain_length", "domain_is_ip", "domain_similarity_to_brand",
        "homograph_indicator", "domain_known_to_registry",
        "dom_element_count", "form_count", "input_count", "button_count",
        "external_script_count", "inline_script_count",
        "login_form_detected", "password_field_detected", "otp_field_detected",
        "same_origin_submission", "cross_origin_submission", "form_secure_transport",
        "redirect_count", "cross_domain_redirect", "credential_requested",
        "password_requested", "otp_requested", "purpose_mismatch",
        "brand_impersonation_indicator", "deceptive_collection_indicator"
    ]
}


def load_split(name: str):
    path = SPLITS_DIR / f"{name}_split.csv"
    df = pd.read_csv(path)
    # Binary label: 1 for phishing, 0 for legitimate
    y = (df["ground_truth"] == "phishing").astype(int).values
    return df, y


def train_and_evaluate():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    df_train, y_train = load_split("train")
    df_val, y_val = load_split("validation")
    df_test, y_test = load_split("test")

    model_configs = {
        "Logistic_Regression": lambda: LogisticRegression(max_iter=1000, random_state=42),
        "Random_Forest": lambda: RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42),
        "Gradient_Boosting": lambda: GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42),
    }

    results = {}

    print("================================================================================")
    print("TRAINING CAPSTONE-1 MODELS ACROSS 5 FEATURE GROUPS")
    print("================================================================================")

    for group_name, features in FEATURE_GROUPS.items():
        results[group_name] = {}
        X_train = df_train[features].astype(float).values
        X_val = df_val[features].astype(float).values
        X_test = df_test[features].astype(float).values

        for model_name, model_fn in model_configs.items():
            model = model_fn()
            t0 = time.perf_counter()
            model.fit(X_train, y_train)
            train_time_ms = (time.perf_counter() - t0) * 1000

            # Predict on Val and Test
            t_inf_0 = time.perf_counter()
            y_pred_test = model.predict(X_test)
            inf_time_ms = ((time.perf_counter() - t_inf_0) * 1000) / len(X_test)

            y_prob_test = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred_test

            acc = accuracy_score(y_test, y_pred_test)
            prec = precision_score(y_test, y_pred_test, zero_division=0)
            rec = recall_score(y_test, y_pred_test, zero_division=0)
            f1 = f1_score(y_test, y_pred_test, zero_division=0)

            # False Positive Rate (FPR) = FP / (FP + TN)
            cm = confusion_matrix(y_test, y_pred_test, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

            try:
                auc = roc_auc_score(y_test, y_prob_test)
            except Exception:
                auc = 1.0 if acc == 1.0 else 0.5

            entry = {
                "features_count": len(features),
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1_score": round(float(f1), 4),
                "auc_roc": round(float(auc), 4),
                "fpr": round(fpr, 4),
                "fnr": round(fnr, 4),
                "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
                "train_time_ms": round(train_time_ms, 3),
                "single_inference_latency_ms": round(inf_time_ms, 3),
            }
            results[group_name][model_name] = entry
            print(f"[{group_name}] {model_name:20s} | Acc: {acc:.2f} | F1: {f1:.2f} | FPR: {fpr:.2f} | Latency: {inf_time_ms:.3f}ms")

    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("================================================================================")
    print(f"All training results saved to {RESULTS_JSON}")
    print("================================================================================")


def train_event_models(dataset_path):
    """Controlled engineering comparison. Never claims independent domain/brand validation."""
    import hashlib
    from sklearn.model_selection import LeaveOneGroupOut
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import average_precision_score, precision_recall_curve, auc
    data = json.loads(Path(dataset_path).read_text(encoding="utf-8"))
    rows = data["episodes"]
    if data.get("provenance") != "CONTROLLED" or len(rows) != 24:
        raise ValueError("Expected complete controlled browser shakedown dataset")
    expected = {(str(f), label, layout) for f in range(1, 7) for label in (0, 1) for layout in (0, 1)}
    if {(r['family'], r['label'], r['layout']) for r in rows} != expected:
        raise ValueError('Missing or duplicated controlled cases')
    for row in rows:
        features = row['representations']
        if features.get('version') != 'event-features-1' or len(features['flat_vector']) != 14 or len(features['relationship_vector']) != 22:
            raise ValueError('Feature schema mismatch')
        if features['relationship_vector'][:14] != features['flat_vector'] or features['flat_vector'][0] != len(row['events']):
            raise ValueError('Representations do not share the same observation baseline')
        if any(not np.isfinite(v) or v < 0 for v in features['relationship_vector']):
            raise ValueError('Invalid feature parameters')
        raw = json.dumps(row["events"], ensure_ascii=False, separators=(",", ":")).encode()
        if hashlib.sha256(raw).hexdigest() != row["events_sha256"] or row["dropped"]:
            raise ValueError("Invalid or incomplete event evidence")
        if row["provenance"] != "CONTROLLED":
            raise ValueError("Provenance must not be silently mixed")
    y = np.array([r["label"] for r in rows])
    groups = np.array([r["template_group"] for r in rows])
    configs = {
        "LogisticRegression": lambda: make_pipeline(StandardScaler(), LogisticRegression(C=1, max_iter=2000, random_state=42)),
        "RandomForest": lambda: RandomForestClassifier(n_estimators=50, max_depth=3, random_state=42),
        "GradientBoosting": lambda: GradientBoostingClassifier(n_estimators=30, max_depth=2, random_state=42),
    }
    def metrics(labels, scores):
        predicted = scores >= 0.5
        tn, fp, fn, tp = confusion_matrix(labels, predicted, labels=[0, 1]).ravel()
        both = len(set(labels)) == 2
        precision_curve, recall_curve, _ = precision_recall_curve(labels, scores)
        return dict(precision=float(precision_score(labels, predicted, zero_division=0)),
                    recall=float(recall_score(labels, predicted, zero_division=0)),
                    f1=float(f1_score(labels, predicted, zero_division=0)),
                    average_precision=float(average_precision_score(labels, scores)) if both else None,
                    pr_auc=float(auc(recall_curve, precision_curve)) if both else None,
                    roc_auc=float(roc_auc_score(labels, scores)) if both else None,
                    fpr=float(fp / (fp + tn)) if fp + tn else None,
                    fnr=float(fn / (fn + tp)) if fn + tp else None)
    report = dict(provenance="CONTROLLED", episode_count=len(rows), independent_authored_families=len(set(groups)),
                  threshold=0.5, domain_split="UNAVAILABLE: one loopback domain group", brand_split="UNAVAILABLE: no verified brand labels",
                  limitation="Engineering shakedown; authored labels, dependent layouts, no real-world calibration or graph superiority claim.", results={})
    for representation in ("flat", "relationship"):
        X = np.array([r["representations"][representation + "_vector"] for r in rows], dtype=float)
        report["results"][representation] = {}
        for name, factory in configs.items():
            scores = np.full(len(rows), np.nan)
            for train, test in LeaveOneGroupOut().split(X, y, groups):
                if set(groups[train]) & set(groups[test]): raise ValueError("Group leakage")
                model = factory().fit(X[train], y[train])
                scores[test] = model.predict_proba(X[test])[:, 1]
            # Later layout collected after earlier layout: chronological but not independent templates.
            train = np.array([i for i, r in enumerate(rows) if r["layout"] == 0])
            test = np.array([i for i, r in enumerate(rows) if r["layout"] == 1])
            if max(rows[i]["collected_at"] for i in train) >= min(rows[i]["collected_at"] for i in test):
                raise ValueError("Temporal order violated")
            temporal = factory().fit(X[train], y[train]).predict_proba(X[test])[:, 1]
            report["results"][representation][name] = dict(template_group_holdout=metrics(y, scores),
                temporal_layout_holdout=metrics(y[test], temporal), predictions=scores.tolist())
            for grouping in ('domain_group', 'brand_group'):
                values = [r.get(grouping) for r in rows]
                if any(v is None for v in values) or len(set(values)) < 2:
                    report['results'][representation][name][grouping + '_holdout'] = {'status': 'UNAVAILABLE', 'reason': 'Missing labels or fewer than two groups'}
                    continue
                group_values = np.array(values)
                grouped_scores = np.full(len(rows), np.nan)
                valid = True
                for grouped_train, grouped_test in LeaveOneGroupOut().split(X, y, group_values):
                    if len(set(y[grouped_train])) < 2:
                        valid = False; break
                    grouped_scores[grouped_test] = factory().fit(X[grouped_train], y[grouped_train]).predict_proba(X[grouped_test])[:, 1]
                report['results'][representation][name][grouping + '_holdout'] = metrics(y, grouped_scores) if valid else {'status': 'UNAVAILABLE', 'reason': 'Single-class training group'}
    flat = report["results"]["flat"]["LogisticRegression"]["template_group_holdout"]["pr_auc"]
    graph = report["results"]["relationship"]["LogisticRegression"]["template_group_holdout"]["pr_auc"]
    report["relationship_minus_flat_pr_auc"] = graph - flat
    report["decision"] = "EXPLORATORY_GAIN" if graph > flat + .02 else "REDESIGN_RELATIONSHIPS" if graph < flat - .02 else "WITHIN_EXPLORATORY_MARGIN"
    # Preselected transparent local candidate; exploratory scores do not authorize autonomous blocking.
    representation = "relationship" if graph > flat + .02 else "flat"
    X = np.array([r["representations"][representation + "_vector"] for r in rows], dtype=float)
    model = configs["LogisticRegression"]().fit(X, y)
    scaler, classifier = model[0], model[1]
    artifact = dict(model_id="controlled-event-lr-1", feature_version="event-features-1", representation=representation,
                    provenance="CONTROLLED", calibrated=False, autonomous_blocking=False,
                    mean=scaler.mean_.tolist(), scale=scaler.scale_.tolist(),
                    coefficients=classifier.coef_[0].tolist(), intercept=float(classifier.intercept_[0]),
                    dataset_sha256=hashlib.sha256(Path(dataset_path).read_bytes()).hexdigest())
    root = Path(__file__).resolve().parents[2]
    artifact["parity_cases"] = [{"features": vector.tolist(), "score": float(score)} for vector, score in zip(X, model.predict_proba(X)[:, 1])]
    (root / "browser-extension/assets/event-model.json").write_text(json.dumps(artifact, indent=2)+"\n")
    report["deployment"] = artifact
    report["parity_cases"] = [{"features": vector.tolist(), "score": float(score)} for vector, score in zip(X, model.predict_proba(X)[:, 1])]
    (root / ".runtime/event-model-evaluation.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({key: report[key] for key in ("episode_count", "decision", "relationship_minus_flat_pr_auc")}))


def train_contextual_models(dataset_path, output_dir=None):
    """Final-approach flat candidate experiment, without touching deployed assets.

    Selection uses a separate set. Calibration sees only calibration labels, and
    the fixed test set is scored after selection and calibration are frozen.
    Synthetic/controlled data can exercise the pipeline but cannot pass release.
    """
    import hashlib
    import importlib.metadata
    import platform
    import sys
    from datetime import datetime, timezone
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from ml.data.build_context_dataset import extract_features
    from ml.evaluation.contextual_eval import (PARTITIONS, contextual_metrics,
        observable_ambiguity, validate_context_dataset)

    path = Path(dataset_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("episodes", [])
    # Validate source vectors against the exact current extension extractor.
    extracted = extract_features(rows)
    features = extracted["feature_names"]
    indices, manifest = validate_context_dataset(data, features)
    for row, actual in zip(rows, extracted["extracted"], strict=True):
        if row["feature_vector"] != actual["vector"]:
            raise ValueError("Stored contextual features differ from the current TypeScript extractor")
    output = Path(output_dir) if output_dir else MODELS_DIR / "contextual-candidate"
    output.mkdir(parents=True, exist_ok=True)
    X = np.asarray([row["feature_vector"] for row in rows], dtype=np.float64)
    y = np.asarray([row["ground_truth"] for row in rows], dtype=int)
    train, selection, calibration, test = (np.asarray(indices[name]) for name in PARTITIONS)
    configs = {
        "LogisticRegression": lambda: make_pipeline(StandardScaler(), LogisticRegression(C=1, max_iter=2000, random_state=42)),
        "RandomForest": lambda: RandomForestClassifier(n_estimators=100, max_depth=4, min_samples_leaf=2, random_state=42, n_jobs=1),
        "GradientBoosting": lambda: GradientBoostingClassifier(n_estimators=60, max_depth=2, min_samples_leaf=2, random_state=42),
    }
    report = dict(protocol="contextual-training-1", generated_at=datetime.now(timezone.utc).isoformat(),
        status="EXPERIMENTALLY_VERIFIED_SYNTHETIC_PIPELINE" if data["provenance"] == "SYNTHETIC" else "CANDIDATE_EXPERIMENT",
        provenance=data["provenance"], dataset_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        dataset_path=str(path.resolve()), episode_count=len(rows), feature_version="context-features-1",
        representation="contextual-flat", feature_names=features, seed=42, split_manifest=manifest,
        protocol_controls=dict(model_selection="Maximum selection-set average precision; ties use lower Brier score, then declaration order.",
            calibration="Independent calibration set: sigmoid fit on clipped base log odds; no refit on test data.",
            threshold=0.5, threshold_policy="Predeclared diagnostic threshold; not a prevention operating point.",
            test_policy="Evaluated after selected model and calibration parameters are frozen; not used for selection.",
            confidence_policy="Calibration on authored data is not real-world confidence.",
            hyperparameters_fixed=True),
        environment=dict(python=platform.python_version(), packages={name: importlib.metadata.version(name)
            for name in ("numpy", "scikit-learn", "onnx", "onnxruntime", "skl2onnx")}),
        source_hashes={name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in
            ("ml/training/train_models.py", "ml/evaluation/contextual_eval.py", "ml/data/build_context_dataset.py", "browser-extension/src/core/tsfeg.ts")},
        limitations=data.get("limitations", []), model_comparison={}, artifacts={})
    models = {}
    for name, factory in configs.items():
        start = time.perf_counter()
        model = factory().fit(X[train], y[train])
        elapsed = (time.perf_counter() - start) * 1000
        models[name] = model
        report["model_comparison"][name] = dict(fit_partition="train", fit_samples=len(train), train_time_ms=elapsed,
            selection=contextual_metrics(y[selection], model.predict_proba(X[selection])[:, 1]))
    selected = min(models, key=lambda name: (-report["model_comparison"][name]["selection"]["average_precision"],
        report["model_comparison"][name]["selection"]["brier_score"], list(models).index(name)))
    report["selected_model"] = selected

    def log_odds(scores):
        bounded = np.clip(np.asarray(scores), 1e-7, 1 - 1e-7)
        return np.log(bounded / (1 - bounded))

    def calibrated_scores(scores, params):
        logits = np.clip(params["coefficient"] * log_odds(scores) + params["intercept"], -700, 700)
        return 1 / (1 + np.exp(-logits))

    # Fit calibration independently for each fixed candidate. The winner was
    # already selected. No calibration/test result can change that selection.
    calibrators = {}
    for name, model in models.items():
        raw_calibration = model.predict_proba(X[calibration])[:, 1]
        calibrator = LogisticRegression(C=1e6, max_iter=2000, random_state=42).fit(log_odds(raw_calibration).reshape(-1, 1), y[calibration])
        params = dict(method="sigmoid", coefficient=float(calibrator.coef_[0, 0]), intercept=float(calibrator.intercept_[0]),
            input="base_log_odds", fit_partition="calibration", fit_sample_count=len(calibration),
            evidence_scope=data["provenance"], real_world_calibration_verified=False)
        calibrators[name] = params
        raw = model.predict_proba(X[test])[:, 1]
        adjusted = calibrated_scores(raw, params)
        report["model_comparison"][name].update(calibration=params,
            test_uncalibrated=contextual_metrics(y[test], raw), test_calibrated=contextual_metrics(y[test], adjusted))
    report["observable_ambiguity"] = observable_ambiguity([rows[i] for i in test])
    model = models[selected]
    all_raw = model.predict_proba(X)[:, 1]
    all_calibrated = calibrated_scores(all_raw, calibrators[selected])
    report["test_predictions"] = [dict(session_id=rows[i]["session_id"], ground_truth=int(y[i]),
        base_score=float(all_raw[i]), calibrated_score=float(all_calibrated[i]), scenario=rows[i].get("scenario", "unknown")) for i in test]
    by_service = sorted({rows[i]["service_category"] for i in test})
    report["test_by_service_category"] = {category: contextual_metrics(
        y[[i for i in test if rows[i]["service_category"] == category]],
        all_calibrated[[i for i in test if rows[i]["service_category"] == category]]) for category in by_service}

    # Portable transparent LR candidate remains separately named if the model
    # comparison selected another family. Existing browser assets are preserved.
    scaler, lr = models["LogisticRegression"][0], models["LogisticRegression"][1]
    lr_raw = models["LogisticRegression"].predict_proba(X)[:, 1]
    lr_scores = calibrated_scores(lr_raw, calibrators["LogisticRegression"])
    artifact = dict(model_id="contextual-synthetic-lr-1" if data["provenance"] == "SYNTHETIC" else "contextual-lr-candidate-1",
        feature_version="context-features-1", feature_names=features, representation="contextual-flat",
        provenance=data["provenance"], status="RESEARCH_CANDIDATE_ONLY", selected_model=(selected == "LogisticRegression"),
        calibrated=True, calibration=calibrators["LogisticRegression"], real_world_calibration_verified=False,
        autonomous_blocking=False, production_ready=False, dataset_sha256=report["dataset_sha256"],
        mean=scaler.mean_.tolist(), scale=scaler.scale_.tolist(), coefficients=lr.coef_[0].tolist(), intercept=float(lr.intercept_[0]),
        parity_cases=[dict(features=vector.tolist(), base_score=float(base_score), score=float(score))
            for vector, base_score, score in zip(X, lr_raw, lr_scores, strict=True)])
    lr_path = output / "contextual-lr-candidate.json"
    lr_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    report["artifacts"]["logistic_json"] = dict(path=str(lr_path.resolve()), sha256=hashlib.sha256(lr_path.read_bytes()).hexdigest(),
        selected=(selected == "LogisticRegression"))

    # Export only candidate ONNX files. Probability parity is checked on every
    # available vector, including held-out samples (without fitting to them).
    import onnx
    import onnxruntime as ort
    from onnx import TensorProto, helper, numpy_helper
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    exported = convert_sklearn(model, initial_types=[("features", FloatTensorType([None, len(features)]))],
        options={id(model): {"zipmap": False}}, target_opset=17)
    probability_output = exported.graph.output[1].name
    params = calibrators[selected]
    constants = {"context_index": np.array([1], dtype=np.int64), "context_min": np.array(1e-7, dtype=np.float32),
        "context_max": np.array(1 - 1e-7, dtype=np.float32), "context_one": np.array(1, dtype=np.float32),
        "context_slope": np.array(params["coefficient"], dtype=np.float32), "context_bias": np.array(params["intercept"], dtype=np.float32)}
    exported.graph.initializer.extend([numpy_helper.from_array(value, name=name) for name, value in constants.items()])
    exported.graph.node.extend([
        helper.make_node("Gather", [probability_output, "context_index"], ["context_probability"], axis=1),
        helper.make_node("Clip", ["context_probability", "context_min", "context_max"], ["context_bounded"]),
        helper.make_node("Sub", ["context_one", "context_bounded"], ["context_complement"]),
        helper.make_node("Div", ["context_bounded", "context_complement"], ["context_odds"]),
        helper.make_node("Log", ["context_odds"], ["context_logit"]),
        helper.make_node("Mul", ["context_logit", "context_slope"], ["context_scaled"]),
        helper.make_node("Add", ["context_scaled", "context_bias"], ["context_calibrated_logit"]),
        helper.make_node("Sigmoid", ["context_calibrated_logit"], ["calibrated_risk"]),
    ])
    exported.graph.output.append(helper.make_tensor_value_info("calibrated_risk", TensorProto.FLOAT, [None, 1]))
    helper.set_model_props(exported, {"model_status": "RESEARCH_CANDIDATE_ONLY", "provenance": data["provenance"],
        "feature_version": "context-features-1", "feature_names": json.dumps(features),
        "autonomous_blocking": "false", "dataset_sha256": report["dataset_sha256"]})
    onnx.checker.check_model(exported)
    onnx_path = output / "contextual-selected-candidate.onnx"
    onnx_path.write_bytes(exported.SerializeToString())
    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    outputs = session.run(None, {"features": X.astype(np.float32)})
    by_name = dict(zip([value.name for value in session.get_outputs()], outputs, strict=True))
    raw_error = float(np.max(np.abs(by_name[probability_output][:, 1] - all_raw)))
    calibrated_error = float(np.max(np.abs(by_name["calibrated_risk"].ravel() - all_calibrated)))
    parity = raw_error <= 1e-5 and calibrated_error <= 1e-5
    report["artifacts"]["selected_onnx"] = dict(path=str(onnx_path.resolve()), sha256=hashlib.sha256(onnx_path.read_bytes()).hexdigest(),
        selected_model=selected, feature_count=len(features), output_names=[value.name for value in session.get_outputs()],
        parity=dict(status="PASS" if parity else "FAIL", vectors=len(X), tolerance=1e-5,
            maximum_base_probability_error=raw_error, maximum_calibrated_probability_error=calibrated_error))
    reasons = ["Independent external evaluation and prevention operating-point approval have not been completed."]
    if data["provenance"] in ("SYNTHETIC", "CONTROLLED"):
        reasons.append(f"{data['provenance']} authored samples cannot establish real-world generalization or calibration.")
    for grouping in ("domain_group", "brand_group", "template_group", "temporal"):
        check = manifest["group_checks"][grouping]
        if check["status"] != "PASS" or check.get("scope") == "SYNTHETIC_PIPELINE_ONLY":
            reasons.append(f"Independent {grouping} generalization is UNVERIFIED.")
    if not parity:
        reasons.append("ONNX score parity failed.")
    report["release_gate"] = dict(status="BLOCKED", deploy=False, autonomous_blocking=False, reasons=reasons)
    report_path = output / "contextual-training-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(dict(protocol=report["protocol"], dataset_sha256=report["dataset_sha256"],
        report_sha256=hashlib.sha256(report_path.read_bytes()).hexdigest(), selected_model=selected,
        source_hashes=report["source_hashes"], artifacts=report["artifacts"], release_gate=report["release_gate"]), indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(report=str(report_path.resolve()), selected_model=selected,
        test=report["model_comparison"][selected]["test_calibrated"], release_gate=report["release_gate"], onnx_parity=parity), indent=2))
    if not parity:
        raise RuntimeError("Candidate saved for debugging; ONNX parity failed and release remains blocked")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--events", type=Path, help="Historical controlled event experiment (updates legacy event asset)")
    mode.add_argument("--contextual", type=Path, help="Final-approach contextual candidate experiment; never promotes assets")
    parser.add_argument("--output-dir", type=Path, help="Contextual candidate artifact directory")
    args = parser.parse_args()
    if args.contextual:
        train_contextual_models(args.contextual, args.output_dir)
    elif args.events:
        train_event_models(args.events)
    else:
        train_and_evaluate()
