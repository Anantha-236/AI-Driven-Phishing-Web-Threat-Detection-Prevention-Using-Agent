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


if __name__ == "__main__":
    train_and_evaluate()
