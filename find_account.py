"""
Find which evidence file contains account_4857 and how to map it.
"""
import csv, json, sys, re
from pathlib import Path

sys.path.insert(0, str(Path('code').resolve()))
from main import AuditOrchestrator
from temporal_filter import is_admissible

orch = AuditOrchestrator(repo_root=Path('.').resolve())

# Search index for account_4857
print("Searching for account_4857 in index:")
for tok, recs in orch.evidence_index.records_by_token.items():
    for r in recs:
        if r.get('resource_id') == 'account_4857':
            print(f"  tok={tok} ev={r.get('evidence_id')} exists={r.get('exists')} cap={r.get('captured_at')}")

print()

# Search all evidence files directly for account_4857
evidence_base = Path('dataset/evidence')
for fpath in sorted(evidence_base.rglob('*')):
    if fpath.is_file() and fpath.suffix in ['.json', '.sql', '.log', '.txt']:
        try:
            txt = fpath.read_text(encoding='utf-8', errors='replace')
            if 'account_4857' in txt:
                print(f"FOUND in {fpath.name}")
                # Show context
                idx = txt.index('account_4857')
                print(f"  Context: ...{txt[max(0,idx-100):idx+100]}...")
        except Exception as e:
            print(f"  Error in {fpath.name}: {e}")

print()
# Also check system_activity for account_4857
with open('dataset/system_activity.csv', newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        if row.get('resource_id') == 'account_4857':
            print(f"system_activity: {row}")
