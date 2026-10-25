"""
Detailed analysis of per-case failures.
"""
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path('code').resolve()))
from main import AuditOrchestrator

orch = AuditOrchestrator(repo_root=Path('.').resolve())

with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    sample_cases = list(csv.DictReader(f))

predictions = {}
for case in sample_cases:
    result = orch.audit_case(case)
    predictions[case['case_id']] = result

with open('dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    gold = {r['case_id']: r for r in csv.DictReader(f)}

failure_types = {}

for case_id in sorted(gold.keys()):
    g = gold[case_id]
    p = predictions.get(case_id)
    if not p:
        continue

    g_steps = json.loads(g['steps_json'])
    p_steps = json.loads(p['steps_json'])

    def step_sig(s):
        return (s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'])

    g_sigs = [step_sig(s) for s in g_steps]
    p_sigs = [step_sig(s) for s in p_steps]

    if g_sigs == p_sigs:
        continue  # Perfect

    # Compare
    g_resources = set((s['system_id'], s['resource_id']) for s in g_steps)
    p_resources = set((s['system_id'], s['resource_id']) for s in p_steps)

    missing_resources = g_resources - p_resources
    extra_resources = p_resources - g_resources

    # Check if correct resources but wrong resource_id
    g_sids = set(s['system_id'] for s in g_steps)
    p_sids = set(s['system_id'] for s in p_steps)
    sys_match = (g_sids == p_sids)

    # Account resource issue
    g_accts = [s['resource_id'] for s in g_steps if s['system_id'] == 'account_service']
    p_accts = [s['resource_id'] for s in p_steps if s['system_id'] == 'account_service']

    print(f"\n{case_id} [{g['deletion_status']}]  gold={len(g_steps)}steps pred={len(p_steps)}steps")
    if missing_resources:
        print(f"  MISSING: {missing_resources}")
    if extra_resources:
        print(f"  EXTRA:   {extra_resources}")
    if g_accts != p_accts:
        print(f"  ACCOUNT resource: gold={g_accts} pred={p_accts}")

    # Check evidence ids on COMPLETE cases
    if g['deletion_status'] == 'COMPLETE':
        g_evids = set(s['evidence_id'] for s in g_steps)
        p_evids = set(s['evidence_id'] for s in p_steps)
        if g_evids != p_evids:
            print(f"  EVIDENCE: gold={g_evids} pred={p_evids}")
