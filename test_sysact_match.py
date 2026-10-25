import csv, json
from datetime import datetime

requests = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
sys_act = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))
gold = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8'))}

# Deletion worker account_service DELETE_RECORD events
dw_accts = [r for r in sys_act if r['source_system'] == 'deletion_worker' and r['target_system'] == 'account_service' and r['event_type'] == 'DELETE_RECORD']

for req in requests:
    cid = req['case_id']
    g = gold[cid]
    g_steps = json.loads(g['steps_json'])
    g_accts = [s['resource_id'] for s in g_steps if s['system_id'] == 'account_service']
    g_acct = g_accts[0] if g_accts else None
    
    rep_at = req['reported_at']
    rep_dt = datetime.fromisoformat(rep_at.replace('Z', '+00:00'))
    
    # find dw_accts within 3 hours before reported_at
    nearby = []
    for d in dw_accts:
        evt_dt = datetime.fromisoformat(d['event_time'].replace('Z', '+00:00'))
        diff_hours = (rep_dt - evt_dt).total_seconds() / 3600.0
        if 0 <= diff_hours <= 3.0:
            nearby.append((d['resource_id'], diff_hours, d['activity_id']))
    
    print(f"{cid} ({req['email']}) reported_at={rep_at}: gold={g_acct} -> nearby in sys_act: {nearby}")
