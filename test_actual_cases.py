import sys, os
sys.path.insert(0, os.path.abspath('code'))
from main import AuditOrchestrator
import json, csv

orch = AuditOrchestrator()
with open('dataset/sample_deletion_requests.csv', encoding='utf-8') as f:
    cases = {r['case_id']: r for r in csv.DictReader(f)}

for cid in ['case_24', 'case_25', 'case_26', 'case_31']:
    case = cases[cid]
    result = orch.audit_case(case)
    steps = json.loads(result['steps_json'])
    print(f"=== ACTUAL {cid} | status={result['deletion_status']} | steps={len(steps)} ===")
    for s in steps:
        print(f"  {s['step_no']}. [{s['phase']}] {s['operation']} | sys={s['system_id']} | res={s['resource_id']} | state={s.get('state')} | ev={s['evidence_id']}")
