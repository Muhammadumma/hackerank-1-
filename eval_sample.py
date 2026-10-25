"""
Run pipeline on sample_deletion_requests.csv and compare to sample_output.csv
"""
import csv
import json
import sys
from pathlib import Path

# Add code directory directly
sys.path.insert(0, str(Path('code').resolve()))

from main import AuditOrchestrator

orch = AuditOrchestrator(repo_root=Path('.').resolve())

# Load sample requests
with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    sample_cases = list(csv.DictReader(f))

print(f"Running {len(sample_cases)} sample cases...")
predictions = {}
for case in sample_cases:
    result = orch.audit_case(case)
    predictions[case['case_id']] = result

# Load gold
with open('dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    gold = {r['case_id']: r for r in csv.DictReader(f)}

status_correct = 0
step_count_correct = 0
step_ops_correct = 0
step_full_correct = 0
n = len(gold)

for case_id in sorted(gold.keys()):
    g = gold[case_id]
    p = predictions.get(case_id)
    if not p:
        print(f"{case_id}: MISSING in predictions")
        continue

    g_status = g['deletion_status']
    p_status = p['deletion_status']
    g_steps = json.loads(g['steps_json'])
    p_steps = json.loads(p['steps_json'])

    status_ok = (g_status == p_status)
    if status_ok:
        status_correct += 1

    count_ok = (len(g_steps) == len(p_steps))
    if count_ok:
        step_count_correct += 1

    g_ops = [(s['phase'], s['operation']) for s in g_steps]
    p_ops = [(s['phase'], s['operation']) for s in p_steps]
    ops_ok = (g_ops == p_ops)
    if ops_ok:
        step_ops_correct += 1

    def step_sig(s):
        return (s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'])

    g_sigs = [step_sig(s) for s in g_steps]
    p_sigs = [step_sig(s) for s in p_steps]
    full_ok = (g_sigs == p_sigs)
    if full_ok:
        step_full_correct += 1

    if not status_ok or not full_ok:
        print(f"\n{'='*60}")
        print(f"CASE {case_id}")
        print(f"  Status: gold={g_status} pred={p_status} {'OK' if status_ok else 'MISMATCH'}")
        print(f"  Step count: gold={len(g_steps)} pred={len(p_steps)}")
        print(f"  GOLD steps:")
        for s in g_steps:
            print(f"    [{s['phase']}] {s['operation']} {s['system_id']}:{s['resource_id']} ev={s['evidence_id']}")
        print(f"  PRED steps:")
        for s in p_steps:
            print(f"    [{s['phase']}] {s['operation']} {s['system_id']}:{s['resource_id']} ev={s['evidence_id']}")

print(f"\n{'='*60}")
print(f"SUMMARY: {n} sample cases")
print(f"  Status accuracy:    {status_correct}/{n}")
print(f"  Step count match:   {step_count_correct}/{n}")
print(f"  Ops sequence match: {step_ops_correct}/{n}")
print(f"  Full step match:    {step_full_correct}/{n}")
