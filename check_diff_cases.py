import json, csv

gold = {r['case_id']: r for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8'))}
for cid in ['case_21', 'case_24', 'case_03', 'case_04', 'case_29', 'case_30']:
    print(f"=== {cid} ===")
    for s in json.loads(gold[cid]['steps_json']):
        print(f"  [{s['phase']}] {s['system_id']}:{s['resource_id']} {s['operation']}")
