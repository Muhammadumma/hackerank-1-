"""
Trace exactly how the account resource lookup works for a specific case.
"""
import csv, json, sys
from pathlib import Path

sys.path.insert(0, str(Path('code').resolve()))
from main import AuditOrchestrator
from temporal_filter import is_admissible

orch = AuditOrchestrator(repo_root=Path('.').resolve())

# Let's look at case_24 - Keiko Nakamura
# gold: account_5334 in search, account resource=account_5334 (WAIT - gold is account_5334 for search but account resource should be different)
# Actually looking at gold for case_24: FINDING account_service:account_5334 -- so the account IS account_5334
# But our pred says account_5334 is ALSO correct here!
# Actually wait - look again - in case_24 GOLD, account_5334 is a FINDING (PRESENT), meaning it should have been deleted
# So account_5334 IS the right account, but we're then ALSO including account_5334 as extra with the batch linking

# Let's look at the user for case_24
with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    cases = {r['case_id']: r for r in csv.DictReader(f)}

# Case_24 keiko.nakamura@gmail.com
case = cases['case_24']
print("Case_24 email:", case['email'])
print("audit_at:", case['audit_at'])

user_id = orch.identity_resolver.resolve_user_id(case['email'], case['audit_at'])
print("Resolved user_id:", user_id)

idents = orch.identity_resolver.get_all_identifiers(case['email'], case['audit_at'])
print("All identifiers:", idents)

obs = orch.evidence_index.query_observations(idents, case['audit_at'])
print(f"\nObservations ({len(obs)}):")
for o in obs:
    print(f"  {o.get('system_id')}:{o.get('resource_id')} exists={o.get('exists')} has_pii={o.get('has_pii')} ev={o.get('evidence_id')} cap={o.get('captured_at')}")

canonical = orch._get_canonical_account_resource(case['email'], user_id, obs)
print(f"\nCanonical account: {canonical}")
print(f"Expected: account_5334 (gold) + search_5577")
