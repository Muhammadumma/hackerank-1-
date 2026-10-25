"""
Forensic comparison of generated output vs sample_output.
Reports step-by-step diffs on each of the 32 sample cases.
"""
import csv
import json

def load_csv(path):
    with open(path, newline='', encoding='utf-8') as f:
        return {r['case_id']: r for r in csv.DictReader(f)}

gold = load_csv(r'dataset/sample_output.csv')
pred = load_csv(r'output.csv')

status_correct = 0
step_count_correct = 0
step_ops_correct = 0
step_full_correct = 0

for case_id in sorted(gold.keys()):
    g = gold[case_id]
    p = pred.get(case_id)
    if not p:
        print(f"{case_id}: MISSING in output")
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

    # Compare operations+phases only (ignore resource/evidence ids)
    g_ops = [(s['phase'], s['operation']) for s in g_steps]
    p_ops = [(s['phase'], s['operation']) for s in p_steps]
    ops_ok = (g_ops == p_ops)
    if ops_ok:
        step_ops_correct += 1

    # Full step-level match (system_id, resource_id, operation, phase, state)
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
        print(f"  Step count: gold={len(g_steps)} pred={len(p_steps)} {'OK' if count_ok else 'MISMATCH'}")
        print(f"  Ops match: {ops_ok}")
        print(f"  GOLD steps:")
        for s in g_steps:
            print(f"    [{s['phase']}] {s['operation']} {s['system_id']}:{s['resource_id']} ev={s['evidence_id']}")
        print(f"  PRED steps:")
        for s in p_steps:
            print(f"    [{s['phase']}] {s['operation']} {s['system_id']}:{s['resource_id']} ev={s['evidence_id']}")

n = len(gold)
print(f"\n{'='*60}")
print(f"SUMMARY: {n} sample cases")
print(f"  Status accuracy:    {status_correct}/{n}")
print(f"  Step count match:   {step_count_correct}/{n}")
print(f"  Ops sequence match: {step_ops_correct}/{n}")
print(f"  Full step match:    {step_full_correct}/{n}")
