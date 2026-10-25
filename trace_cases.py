"""
Trace case_24 full audit output vs gold.
"""
import csv, json, sys
from pathlib import Path

sys.path.insert(0, str(Path('code').resolve()))
from main import AuditOrchestrator

orch = AuditOrchestrator(repo_root=Path('.').resolve())

with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    cases = {r['case_id']: r for r in csv.DictReader(f)}

with open('dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    gold = {r['case_id']: r for r in csv.DictReader(f)}

for cid in ['case_24', 'case_25', 'case_31', 'case_32']:
    case = cases[cid]
    result = orch.audit_case(case)
    g = gold[cid]
    g_steps = json.loads(g['steps_json'])
    p_steps = json.loads(result['steps_json'])
    print(f"\n=== {cid} email={case['email']} ===")
    print(f"  GOLD ({len(g_steps)} steps):")
    for s in g_steps:
        print(f"    [{s['phase']}] {s['operation']} {s['system_id']}:{s['resource_id']} ev={s['evidence_id']}")
    print(f"  PRED ({len(p_steps)} steps):")
    for s in p_steps:
        print(f"    [{s['phase']}] {s['operation']} {s['system_id']}:{s['resource_id']} ev={s['evidence_id']}")
