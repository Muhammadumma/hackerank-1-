import sys, os, csv, json
from pathlib import Path
sys.path.insert(0, 'code')
from evidence_loader import EvidenceLoader
from identity_resolver import IdentityResolver

loader = EvidenceLoader(Path('.'))
accounts_by_user = {}

# Test scanning all evidence files for account_ mappings
for f_id in loader.manifest:
    ev = loader.load_evidence(f_id)
    if not ev or not ev.content: continue
    # SQL
    if ev.file_type == 'sql' and isinstance(ev.content, dict):
        for tbl, rows in ev.content.items():
            for r in rows:
                res_id = str(r.get('resource_id', ''))
                if res_id.startswith('account_'):
                    for col in ['email', 'customer_email', 'owner_email', 'user_id', 'customer_reference']:
                        v = r.get(col)
                        if v: accounts_by_user[str(v).lower()] = res_id
    # JSON
    elif ev.file_type == 'json':
        def walk(data):
            if isinstance(data, dict):
                res_id = str(data.get('resource_id', ''))
                if res_id.startswith('account_'):
                    for col in ['email', 'customer_email', 'user_id', 'customer_reference', 'subject_reference']:
                        v = data.get(col)
                        if v: accounts_by_user[str(v).lower()] = res_id
                    prof = data.get('profile') or {}
                    for col in ['email', 'customer_email', 'user_id', 'customer_reference']:
                        v = prof.get(col)
                        if v: accounts_by_user[str(v).lower()] = res_id
                for v in data.values(): walk(v)
            elif isinstance(data, list):
                for item in data: walk(item)
        walk(ev.content)
    # Text / Log
    elif ev.file_type in ['log', 'text'] and isinstance(ev.content, list):
        for line in ev.content:
            if '|' in line:
                parts = [p.strip() for p in line.lstrip('- ').split('|')]
                if len(parts) >= 6:
                    res_id = parts[2]
                    ident = parts[5].lower()
                    if res_id.startswith('account_') and ident:
                        accounts_by_user[ident] = res_id

sample_gold = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8'))}
sample_reqs = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8'))}

print(f"Total discovered accounts: {len(set(accounts_by_user.values()))}")
for cid, req in sample_reqs.items():
    gold = sample_gold[cid]
    gold_steps = json.loads(gold['steps_json'])
    gold_accts = [s['resource_id'] for s in gold_steps if s['system_id'] == 'account_service']
    em = req['email'].lower()
    discovered = accounts_by_user.get(em)
    print(f"{cid} ({em}): gold={gold_accts} -> discovered={discovered}")
