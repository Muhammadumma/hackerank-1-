import csv, json

with open(r'dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

# Show ALL cases
for r in rows:
    steps = json.loads(r['steps_json'])
    phases = [s['phase'] for s in steps]
    ops = [s['operation'] for s in steps]
    sids = list(dict.fromkeys(s['system_id'] for s in steps))
    rids = list(dict.fromkeys(s['resource_id'] for s in steps))
    eids = list(dict.fromkeys(s.get('evidence_id', '') for s in steps))
    print(f"{r['case_id']} [{r['deletion_status']}] steps={len(steps)}")
    print(f"  ops={ops}")
    print(f"  systems={sids}")
    print(f"  resources={rids}")
    print(f"  evidence={eids}")
    print()
