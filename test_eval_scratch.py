import sys, os, csv, json
from pathlib import Path
sys.path.insert(0, 'code')
from main import AuditOrchestrator

orch = AuditOrchestrator()

# Let's inspect what eval_sample would give if we test the sample cases right now
with open('dataset/sample_deletion_requests.csv', newline='', encoding='utf-8') as f:
    sample_cases = list(csv.DictReader(f))

with open('dataset/sample_output.csv', newline='', encoding='utf-8') as f:
    gold = {r['case_id']: r for r in csv.DictReader(f)}

print("Loaded sample cases and gold.")
