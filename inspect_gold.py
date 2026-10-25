import csv, json

with open('dataset/sample_output.csv', encoding='utf-8') as f:
    rows = {r['case_id']: r for r in csv.DictReader(f)}

for cid in ['case_03', 'case_17', 'case_21']:
    r = rows.get(cid, {})
    steps = json.loads(r.get('steps_json', '[]'))
    print(f"=== {cid} | status={r.get('deletion_status')} | total_steps={len(steps)} ===")
    for s in steps:
        print(f"  {s['step_no']}. [{s['phase']}] {s['operation']} | sys={s['system_id']} | res={s['resource_id']} | ev={s['evidence_id']}")
    print()

# Also show all gold statuses and step counts
print("=== FULL SAMPLE OVERVIEW ===")
for cid, r in sorted(rows.items(), key=lambda x: int(x[0].replace('case_',''))):
    steps = json.loads(r.get('steps_json','[]'))
    print(f"  {cid}: {r['deletion_status']:<15} steps={len(steps)}")
