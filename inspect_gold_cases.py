import csv, json

with open('dataset/sample_output.csv', encoding='utf-8') as f:
    rows = {r['case_id']: r for r in csv.DictReader(f)}

for cid in ['case_24', 'case_25', 'case_26', 'case_27', 'case_28', 'case_29', 'case_30', 'case_31', 'case_32']:
    r = rows.get(cid)
    if not r:
        continue
    steps = json.loads(r.get('steps_json', '[]'))
    print(f"=== {cid} | status={r.get('deletion_status')} | steps={len(steps)} ===")
    for s in steps:
        print(f"  {s['step_no']}. [{s['phase']}] {s['operation']} | sys={s['system_id']} | res={s['resource_id']} | state={s.get('state')} | ev={s['evidence_id']}")
    print()
