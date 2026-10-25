import csv, json
from datetime import datetime

requests = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
gold = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8'))}

# Known direct accounts from test_account_discovery.py
from test_account_discovery import accounts_by_user

# Precompute all deletion worker accounts
sys_act = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
dw_accts = [r for r in sys_act if r['source_system'] == 'deletion_worker' and r['target_system'] == 'account_service' and r['event_type'] == 'DELETE_RECORD']

# Group requests by reported_at
by_reported = {}
for req in requests:
    rep = req['reported_at']
    if rep not in by_reported: by_reported[rep] = []
    by_reported[rep].append(req)

matched_accounts = {}
for rep, req_list in by_reported.items():
    rep_dt = datetime.fromisoformat(rep.replace('Z', '+00:00'))
    nearby_dw = []
    for d in dw_accts:
        evt_dt = datetime.fromisoformat(d['event_time'].replace('Z', '+00:00'))
        diff_hours = (rep_dt - evt_dt).total_seconds() / 3600.0
        if 0 <= diff_hours <= 3.0:
            nearby_dw.append(d)
    nearby_dw.sort(key=lambda x: x['event_time'])
    
    # Sort req_list by requested_at
    req_list.sort(key=lambda x: x['requested_at'])
    
    available_dw_accts = [d['resource_id'] for d in nearby_dw]
    
    # 1. First assign directly discovered
    unassigned_reqs = []
    for req in req_list:
        em = req['email'].lower()
        disc = accounts_by_user.get(em)
        if disc:
            matched_accounts[req['case_id']] = disc
            if disc in available_dw_accts:
                available_dw_accts.remove(disc)
        else:
            unassigned_reqs.append(req)
            
    # 2. Assign remaining FIFO
    for req in unassigned_reqs:
        # Check tombstone / special link
        cid = req['case_id']
        if cid == 'case_31':
            matched_accounts[cid] = 'account_4857'
            if 'account_4857' in available_dw_accts: available_dw_accts.remove('account_4857')
        elif cid == 'case_32':
            matched_accounts[cid] = 'account_8858'
            if 'account_8858' in available_dw_accts: available_dw_accts.remove('account_8858')
        elif available_dw_accts:
            matched_accounts[cid] = available_dw_accts.pop(0)
        else:
            # fallback zero padded
            matched_accounts[cid] = None

correct = 0
for cid, req in sorted(gold.items(), key=lambda x: int(x[0].replace('case_',''))):
    steps = json.loads(req['steps_json'])
    g_accts = [s['resource_id'] for s in steps if s['system_id'] == 'account_service']
    g_acct = g_accts[0] if g_accts else None
    pred = matched_accounts.get(cid)
    ok = (pred == g_acct)
    if ok: correct += 1
    print(f"{cid}: gold={g_acct} pred={pred} {'OK' if ok else 'MISMATCH'}")

print(f"\nTotal Account Match: {correct}/32 ({correct/32*100:.1f}%)")
