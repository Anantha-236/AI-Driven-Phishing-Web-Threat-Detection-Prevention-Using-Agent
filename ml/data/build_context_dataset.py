"""Reproducible SYNTHETIC contextual fixtures, never browser collection evidence.

Fixture labels describe authored intent. Some legitimate and phishing sessions have
identical observations deliberately: browser metadata cannot reveal hidden intent.
Domain and brand holdouts remain unavailable; changing fixture origins would not
establish generalization. The production TypeScript extractor produces every vector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FEATURE_VERSION = "context-features-1"


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def extract_features(episodes):
    """Use exactly the deployed source extractor, without a Python reimplementation."""
    source = """
import fs from 'node:fs';
import ts from 'typescript';
const source = fs.readFileSync('browser-extension/src/core/tsfeg.ts', 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
const core = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'));
const rows = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify({ feature_names: core.CONTEXT_FEATURES, extracted: rows.map(row => core.buildContextFeatures(row.events)) }));
"""
    completed = subprocess.run(["node", "--input-type=module", "-e", source], input=json.dumps(episodes),
                               capture_output=True, text=True, encoding="utf-8", cwd=ROOT, check=True)
    return json.loads(completed.stdout)


def build_dataset():
    episodes = []
    # Logical fixture clocks, not collection dates. Template disjointness is a
    # pipeline check only; all fixtures share this generator and six mechanisms.
    for family in range(16):
        partition = "train" if family < 8 else "selection" if family < 10 else "calibration" if family < 12 else "test"
        for case in range(6):
            for label in (0, 1):
                session = f"synthetic-{family:02d}-{case}-{label}"
                base = 1_000_000 + family * 100_000 + case * 10_000
                origin = "https://fixture.invalid"
                target = "https://federation.invalid" if case in (1, 2) else origin
                events = []

                def add(event_type, **fields):
                    seq = len(events) + 1
                    event = dict(event_type=event_type, sensitive_type=None, field_id=None, form_id=None,
                                 frame_origin=origin, target_origin=None, destination_origin=None,
                                 initiator_origin=None, request_type=None, interaction_type=None,
                                 timestamp_ms=base + seq * 100, schema_version="1.2.0", session_id=session,
                                 tab_id=1, document_id=f"doc-{family}-{case}", frame_id=0,
                                 parent_frame_id=None, event_seq=seq, received_ms=base + seq * 100,
                                 trust="ISOLATED_CONTENT_SCRIPT", confidence=1)
                    event.update(fields)
                    events.append(event)

                add("DOCUMENT_STARTED")
                purpose = "PAYMENT" if case == 1 else "RECOVERY" if case == 5 else "LOGIN"
                if label and case in (4, 5):
                    purpose = "INFORMATIONAL" if case == 4 else "DOWNLOAD"
                add("PAGE_CONTEXT_OBSERVED", page_purpose=purpose, purpose_source="STATIC_SEMANTICS")
                # Template variations are genuine event-structure changes, but
                # are still synthetic relatives of this same authored generator.
                for _ in range(family % 3):
                    add("DOM_MUTATION")
                if family % 4 == 1:
                    add("FRAME_CREATED", frame_id=1, parent_frame_id=0,
                        frame_origin="https://federation.invalid")
                add("FORM_DISCOVERED", form_id="f-1", target_origin=target)
                sensitive = "CARD" if case == 1 else "OTP" if case == 5 else "PASSWORD"
                add("FIELD_DISCOVERED", form_id="f-1", field_id="e-1", sensitive_type=sensitive)
                add("FORM_TARGET_OBSERVED", form_id="f-1", target_origin=target)
                add("SENSITIVE_INTERACTION", form_id="f-1", field_id="e-1",
                    sensitive_type=sensitive, interaction_type="focus")
                if case == 3:
                    add("FIELD_DISCOVERED", form_id="f-1", field_id="e-2", sensitive_type="OTP")
                    add("SENSITIVE_INTERACTION", form_id="f-1", field_id="e-2",
                        sensitive_type="OTP", interaction_type="focus")
                # Target/purpose contradiction pairs expose metadata. For SSO
                # and password/OTP pairs, harmful intent is unobservable.
                if label and case < 2:
                    target = "http://receiver.invalid" if case == 1 else "https://receiver.invalid"
                    add("FORM_TARGET_CHANGED", form_id="f-1", target_origin=target)
                elif family % 4 == 2:
                    add("FORM_TARGET_OBSERVED", form_id="f-1", target_origin=target)
                add("REQUEST_OBSERVED", initiator_origin=origin, destination_origin="https://telemetry.invalid",
                    request_type="xmlhttprequest", trust="WEBREQUEST_METADATA")
                add("FORM_SUBMISSION_ATTEMPT", form_id="f-1", target_origin=target,
                    interaction_type="submit", sensitive_type=sensitive)
                episodes.append(dict(session_id=session, ground_truth=label,
                    label_source="SYNTHETIC_AUTHOR_SPEC", label_validated=True,
                    label_validation_reference=f"context-fixtures-1:case-{case}:intent-{label}",
                    provenance="SYNTHETIC", service_category="payment" if case == 1 else "authentication",
                    domain_group=None, brand_group=None, template_group=f"authored-structure-{family:02d}",
                    time_group=family, time_basis="SYNTHETIC_LOGICAL_CLOCK", partition=partition,
                    pair_id=f"synthetic-pair-{family:02d}-{case}",
                    scenario=("target_swap", "payment_downgrade", "opaque_sso", "opaque_password_otp", "informational_password", "download_otp")[case],
                    observable_intent=case not in (2, 3), events=events, events_sha256=canonical_hash(events)))
    extracted = extract_features(episodes)
    for row, features in zip(episodes, extracted["extracted"], strict=True):
        # buildContextFeatures is the single source of truth for feature order.
        row["feature_vector"] = features["vector"]
    return dict(protocol="contextual-training-1", feature_version=FEATURE_VERSION,
                representation="contextual-flat", feature_names=extracted["feature_names"],
                provenance="SYNTHETIC", seed=42,
                limitations=["Not collected from a browser or real websites.",
                    "Authored labels are fixture intent, not independently verified phishing ground truth.",
                    "Synthetic template and logical-time isolation are pipeline checks, not service generalization.",
                    "Domain and brand labels are unavailable. All samples share one authored generator.",
                    "Opaque pairs intentionally share observable features across opposing intent labels."],
                source_hashes={"ml/data/build_context_dataset.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "browser-extension/src/core/tsfeg.ts": hashlib.sha256((ROOT / "browser-extension/src/core/tsfeg.ts").read_bytes()).hexdigest()},
                episodes=episodes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".runtime/contextual-training-dataset.json")
    args = parser.parse_args()
    dataset = build_dataset()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"dataset": str(args.output), "provenance": dataset["provenance"], "episodes": len(dataset["episodes"])}))
