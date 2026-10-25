"""
Trace case_31 account resolution and evidence lookup in detail.
"""
import csv, json, sys
from pathlib import Path

sys.path.insert(0, str(Path('code').resolve()))
from main import AuditOrchestrator
from temporal_filter import is_admissible

orch = AuditOrchestrator(repo_root=Path('.').resolve())

with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    cases = {r['case_id']: r for r in csv.DictReader(f)}

case = cases['case_31']
print("email:", case['email'])
print("audit_at:", case['audit_at'])

user_id = orch.identity_resolver.resolve_user_id(case['email'], case['audit_at'])
print("user_id:", user_id)

idents = orch.identity_resolver.get_all_identifiers(case['email'], case['audit_at'])
print("identifiers:", idents)

obs = orch.evidence_index.query_observations(idents, case['audit_at'])
print(f"\nObservations ({len(obs)}):")
for o in obs:
    print(f"  {o.get('system_id')}:{o.get('resource_id')} exists={o.get('exists')} has_pii={o.get('has_pii')} ev={o.get('evidence_id')} cap={o.get('captured_at')}")

canonical = orch._get_canonical_account_resource(case['email'], user_id, obs)
print(f"\nCanonical account: {canonical} (expected: account_4857)")

# What's in the index for this user's tokens?
print("\nChecking index for each token:")
for tok in idents:
    recs = orch.evidence_index.records_by_token.get(tok.lower(), [])
    if recs:
        for r in recs:
            print(f"  token={tok} -> {r.get('system_id')}:{r.get('resource_id')} ev={r.get('evidence_id')}")
    else:
        recs2 = orch.evidence_index.records_by_token.get(tok, [])
        if recs2:
            for r in recs2:
                print(f"  token={tok} (exact) -> {r.get('system_id')}:{r.get('resource_id')} ev={r.get('evidence_id')}")

# Check evidence_51 - customer_data_snapshot_bundle_20260915.json
# What's in the index for evidence_51?
print("\nAll records from evidence_51:")
for tok, recs in orch.evidence_index.records_by_token.items():
    for r in recs:
        if r.get('evidence_id') == 'evidence_51' and r.get('captured_at') and is_admissible(r.get('captured_at'), case['audit_at']):
            print(f"  tok={tok} sys={r.get('system_id')} res={r.get('resource_id')} exists={r.get('exists')}")
