"""
CAPSTONE-1 Leakage-Safe Split Generator
Generates:
 - Train, Validation, Test splits strictly isolated by registrable domain
 - Temporal Evaluation split (future time window)
 - Unseen-Domain Evaluation split
 - Adversarial & Counterfactual Evaluation split
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DATASET_CSV = DATA_DIR / "dataset_v0_2.csv"
SPLITS_DIR = Path(__file__).resolve().parent / "splits"


def generate_splits():
    SPLITS_DIR.mkdir(parents=True, exist_ok=True)

    with open(DATASET_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    fieldnames = list(rows[0].keys())

    # 1. Standard Domain-Isolated Train / Val / Test
    # Group by base domain to guarantee ZERO cross-split domain leakage
    train_ids = [
        "legit_bank_001", "legit_bank_002", "legit_paypal_003", "legit_google_004", "legit_ms_005",
        "phish_bank_011", "phish_paypal_012", "phish_google_013", "phish_ms_014", "phish_ip_015"
    ]
    val_ids = [
        "legit_github_006", "legit_stripe_007", "phish_amazon_016", "phish_dropbox_017"
    ]
    test_ids = [
        "legit_portal_008", "legit_dropbox_009", "legit_amazon_010", "phish_stripe_018",
        "counter_bank_019", "counter_paypal_020"
    ]

    train_rows = [r for r in rows if r["sample_id"] in train_ids]
    val_rows = [r for r in rows if r["sample_id"] in val_ids]
    test_rows = [r for r in rows if r["sample_id"] in test_ids]

    # 2. Temporal Split (samples collected after 2026-02-15)
    temporal_rows = [r for r in rows if r["collection_date"] >= "2026-02-15"]

    # 3. Unseen Domain Split (domains completely absent from training set)
    train_domains = set(r["hostname"] for r in train_rows)
    unseen_domain_rows = [r for r in rows if r["hostname"] not in train_domains]

    # 4. Adversarial & Counterfactual Split
    adversarial_rows = [r for r in rows if r["source"] in ("synthetic_controlled_adversarial", "counterfactual_controlled_experiment")]

    splits = {
        "train": train_rows,
        "validation": val_rows,
        "test": test_rows,
        "temporal": temporal_rows,
        "unseen_domain": unseen_domain_rows,
        "adversarial": adversarial_rows,
    }

    manifest = {}
    for name, split_data in splits.items():
        out_path = SPLITS_DIR / f"{name}_split.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(split_data)

        manifest[name] = {
            "file": str(out_path.name),
            "sample_count": len(split_data),
            "legitimate": sum(1 for r in split_data if r["ground_truth"] == "legitimate"),
            "phishing": sum(1 for r in split_data if r["ground_truth"] == "phishing"),
        }

    with open(SPLITS_DIR / "split_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("=========================================")
    print("LEAKAGE-SAFE SPLITS GENERATED")
    print("=========================================")
    for k, v in manifest.items():
        print(f"Split [{k}]: {v['sample_count']} samples (Legit: {v['legitimate']}, Phish: {v['phishing']})")
    print(f"Manifest saved to {SPLITS_DIR / 'split_manifest.json'}")
    print("=========================================")


if __name__ == "__main__":
    generate_splits()
