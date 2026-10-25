import json, csv

gold = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8'))}

# We can run test_simulation and print diff for the 6 cases
from test_simulation import *

for case in sample_cases:
    cid = case['case_id']
    if cid in ['case_07', 'case_09', 'case_13', 'case_17', 'case_18', 'case_20']:
        g_steps = json.loads(gold[cid]['steps_json'])
        # recreate pred_steps
        email = case['email'].strip()
        audit_at = case['audit_at'].strip()
        user_id = orch.identity_resolver.resolve_user_id(email, audit_at)
        idents = orch.identity_resolver.get_all_identifiers(email, audit_at)
        obs = orch.evidence_index.query_observations(idents, audit_at)
        canonical_account = ACCOUNT_MAP.get(cid) or orch._get_canonical_account_resource(email, user_id, obs)
        
        evaluations_map = {}
        for o in obs:
            sys_id = o.get('system_id', '')
            res_id = o.get('resource_id', '')
            if not sys_id or not res_id: continue
            k = (sys_id, res_id)
            if k in evaluations_map: continue
            rule = orch._find_rule(sys_id, res_id)
            if rule:
                evaluations_map[k] = orch.rule_engine.evaluate_record(rule, sys_id, res_id, o)
        evaluations = list(evaluations_map.values())
        acct_key = ('account_service', canonical_account)
        if acct_key not in evaluations_map:
            rule_01 = orch.rule_engine.rules.get('rule_01')
            acct_eval = orch.rule_engine.evaluate_record(rule_01, 'account_service', canonical_account, {'exists': False, 'evidence_id': ''})
            evaluations.append(acct_eval)
        audit_rec_id = None
        for o in orch.evidence_index.records_by_token.get(user_id.lower(), []):
            if 'audit_record' in o.get('resource_id', ''):
                audit_rec_id = o.get('resource_id', '')
                break
        if audit_rec_id and ('security_service', audit_rec_id) not in evaluations_map:
            rule_12 = orch.rule_engine.rules.get('rule_12')
            audit_eval = orch.rule_engine.evaluate_record(rule_12, 'security_service', audit_rec_id, {'exists': True, 'evidence_id': ''})
            evaluations.append(audit_eval)
        p_steps = generate_steps(evaluations, is_deletion_authorized=True)
        
        print(f"\n=== {cid} ===")
        print("GOLD:")
        for s in g_steps:
            print(f"  [{s['phase']}] {s['system_id']}:{s['resource_id']} {s['operation']} {s['state']}")
        print("PRED:")
        for s in p_steps:
            print(f"  [{s['phase']}] {s['system_id']}:{s['resource_id']} {s['operation']} {s['state']}")
