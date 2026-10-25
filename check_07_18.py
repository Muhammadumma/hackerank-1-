import json, csv
from test_simulation import *

for cid in ['case_07', 'case_18']:
    case = [c for c in sample_cases if c['case_id'] == cid][0]
    g_steps = json.loads(gold[cid]['steps_json'])
    
    # print all obs for this user
    email = case['email'].strip()
    audit_at = case['audit_at'].strip()
    user_id = orch.identity_resolver.resolve_user_id(email, audit_at)
    idents = orch.identity_resolver.get_all_identifiers(email, audit_at)
    obs = orch.evidence_index.query_observations(idents, audit_at)
    print(f"\n=== {cid} OBS ({len(obs)}) ===")
    for o in obs:
        print(f"  {o.get('system_id')}:{o.get('resource_id')} exists={o.get('exists')} has_pii={o.get('has_pii')} ev={o.get('evidence_id')}")
    print(f"=== {cid} GOLD ({len(g_steps)}) ===")
    for s in g_steps:
        print(f"  [{s['phase']}] {s['system_id']}:{s['resource_id']} {s['operation']}")
