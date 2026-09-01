from __future__ import annotations

import json
import pickle
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

DATASET_PATH = Path(__file__).resolve().parents[1] / "data" / "dataset_v0_1.csv"
EXPORT_DIR = Path(__file__).resolve().parents[1] / "export"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

CATEGORICAL_COLUMNS = ["claimed_service", "known_brand", "official_domain"]
TARGET_COLUMN = "label"
ID_COLUMN = "sample_id"


def load_dataset() -> pd.DataFrame:
    df = pd.read_csv(DATASET_PATH)
    if df.empty:
        raise ValueError(f"Dataset is empty: {DATASET_PATH}")
    return df


def prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    working = df.copy()
    working[TARGET_COLUMN] = working[TARGET_COLUMN].map({"legitimate": 0, "phishing": 1})
    if working[TARGET_COLUMN].isna().any():
        raise ValueError(f"Unexpected labels found in dataset: {sorted(working[TARGET_COLUMN].dropna().unique().tolist())}")

    X = working.drop(columns=[TARGET_COLUMN, ID_COLUMN, "url", "hostname"], errors="ignore")
    y = working[TARGET_COLUMN]

    X = pd.get_dummies(X, columns=CATEGORICAL_COLUMNS, dummy_na=False)
    X = X.fillna(0)
    return X, y


def evaluate_model(name: str, model, X_train: pd.DataFrame, X_test: pd.DataFrame, y_train: pd.Series, y_test: pd.Series) -> dict:
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, predictions, zero_division=0, average="binary")
    report = classification_report(y_test, predictions, digits=4, zero_division=0)
    result = {
        "model": name,
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "classification_report": report,
    }

    model_path = EXPORT_DIR / f"{name.lower().replace(' ', '_')}_v0_1.pkl"
    with model_path.open("wb") as model_file:
        pickle.dump(model, model_file)

    return result


def main() -> None:
    df = load_dataset()
    X, y = prepare_features(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    models = [
        ("logistic_regression", LogisticRegression(max_iter=5000, class_weight="balanced", random_state=42)),
        ("random_forest", RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")),
    ]

    results = []
    for name, model in models:
        results.append(evaluate_model(name, model, X_train, X_test, y_train, y_test))

    best = sorted(results, key=lambda item: item["f1"], reverse=True)[0]
    metrics_path = EXPORT_DIR / "baseline_metrics_v0_1.json"
    metrics_path.write_text(json.dumps({"results": results, "best_model": best["model"]}, indent=2), encoding="utf-8")

    print("Dataset rows:", len(df))
    print("Train rows:", len(X_train))
    print("Test rows:", len(X_test))
    for item in results:
        print(f"\n=== {item['model']} ===")
        print(f"accuracy={item['accuracy']:.4f}")
        print(f"precision={item['precision']:.4f}")
        print(f"recall={item['recall']:.4f}")
        print(f"f1={item['f1']:.4f}")
        print(item["classification_report"])

    print(f"\nBest model by F1: {best['model']}")


if __name__ == "__main__":
    main()
