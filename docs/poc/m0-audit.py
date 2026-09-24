"""Audit contracts and existing split files; no application or database writes.

Usage: python docs/poc/m0-audit.py <M1 directory> (from project root).
"""
import csv
import importlib.util
import json
from pathlib import Path
import sys

def module_at(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

root = Path.cwd()
m1 = Path(sys.argv[1])
old_models = module_at('audit_old_models', root / 'backend/models.py')
m1_models = module_at('audit_m1_models', m1 / 'backend/app/models.py')
payload = {'collectionId': 'audit', 'timestamp': 1, 'page': {
    'id': 'audit', 'url': 'https://example.test/private-path?token=AUDIT_CANARY',
    'domain': 'example.test', 'title': 'AUDIT_CANARY'},
    'requestedDataTypes': ['AUDIT_CANARY']}
accepted = old_models.ObservationRequest.model_validate(payload).model_dump()
try:
    origin = m1_models._validate_origin('https://audit-user:AUDIT_CANARY@example.test')
    userinfo_accepted = '@' in origin
except ValueError:
    userinfo_accepted = False

splits = {}
for file in (root / 'ml/evaluation/splits').glob('*_split.csv'):
    with file.open(encoding='utf-8-sig', newline='') as stream:
        splits[file.stem.removesuffix('_split')] = list(csv.DictReader(stream))
overlaps = {}
for other in ('validation', 'test', 'temporal', 'adversarial'):
    overlaps[other] = {}
    for field in ('sample_id', 'hostname', 'known_brand'):
        train = {row.get(field) for row in splits['train']} - {'', None}
        heldout = {row.get(field) for row in splits[other]} - {'', None}
        overlaps[other][field] = sorted(train & heldout)
result = {
    'python': sys.version.split()[0],
    'legacy_free_text_and_full_url_accepted': 'AUDIT_CANARY' in json.dumps(accepted),
    'm1_origin_userinfo_accepted': userinfo_accepted,
    'split_counts': {name: len(rows) for name, rows in splits.items()},
    'train_overlap': overlaps,
    'limitations': 'Model validation only; canaries are artificial and never sent to a backend. Hostname overlap is not a registrable-domain audit.',
}
print(json.dumps(result, indent=2))
sys.exit(1 if userinfo_accepted or result['legacy_free_text_and_full_url_accepted'] else 0)
