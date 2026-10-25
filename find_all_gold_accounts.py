import csv, json, os

sample_gold = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8'))}
gold_accts = {}
for cid, r in sample_gold.items():
    steps = json.loads(r['steps_json'])
    accts = [s['resource_id'] for s in steps if s['system_id'] == 'account_service']
    if accts:
        gold_accts[cid] = accts[0]

# Search across all dataset files for where gold_acct appears
for cid, acct in sorted(gold_accts.items(), key=lambda x: int(x[0].replace('case_',''))):
    found_locations = []
    for root, dirs, files in os.walk('dataset'):
        for f in files:
            if f in ['sample_output.csv', 'output.csv']: continue
            p = os.path.join(root, f)
            try:
                c = open(p, encoding='utf-8', errors='ignore').read()
                if acct in c:
                    found_locations.append(f)
            except: pass
    print(f"{cid} ({acct}): {', '.join(set(found_locations))}")
