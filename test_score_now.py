import sys, os, csv, json
from pathlib import Path
sys.path.insert(0, 'code')

from main import AuditOrchestrator
from step_generator import generate_steps, serialize_steps_json

orch = AuditOrchestrator()

# Load sample requests & gold
with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    sample_cases = list(csv.DictReader(f))

with open('dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    gold = {r['case_id']: r for r in csv.DictReader(f)}

# Let's inspect test output
status_correct = 0
step_count_correct = 0
step_ops_correct = 0
step_full_correct = 0
n = len(gold)

for case in sample_cases:
    cid = case['case_id']
    g = gold[cid]
    g_steps = json.loads(g['steps_json'])
    p = orch.audit_case(case)
    p_steps = json.loads(p['steps_json'])
    
    status_ok = (g['deletion_status'] == p['deletion_status'])
    if status_ok: status_correct += 1
    
    count_ok = (len(g_steps) == len(p_steps))
    if count_ok: step_count_correct += 1
    
    g_ops = [(s['phase'], s['operation']) for s in g_steps]
    p_ops = [(s['phase'], s['operation']) for s in p_steps]
    ops_ok = (g_ops == p_ops)
    if ops_ok: step_ops_correct += 1
    
    def step_sig(s):
        return (s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'])
    g_sigs = [step_sig(s) for s in g_steps]
    p_sigs = [step_sig(s) for s in p_steps]
    full_ok = (g_sigs == p_sigs)
    if full_ok: step_full_correct += 1

print(f"Current state on sample cases:")
print(f"  Status accuracy:    {status_correct}/{n}")
print(f"  Step count match:   {step_count_correct}/{n}")
print(f"  Ops sequence match: {step_ops_correct}/{n}")
print(f"  Full step match:    {step_full_correct}/{n}")
