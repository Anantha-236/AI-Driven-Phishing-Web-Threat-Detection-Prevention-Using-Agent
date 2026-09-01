"""
CAPSTONE-1 Generalization Evaluation Suite
Evaluates trained models across 4 distinct evaluation regimes:
 1. In-Distribution Standard Test Split
 2. Temporal Split (future collection window)
 3. Unseen-Domain Split (zero domain overlap with training)
 4. Adversarial & Counterfactual Split
"""

from __future__ import annotations

import json
from pathlib import Path
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

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


if __name__ == "__main__":
    run_generalization()
