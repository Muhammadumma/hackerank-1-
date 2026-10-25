"""
Inspect evidence_51 for user_541 related content.
"""
import json, sys
from pathlib import Path

# evidence_51 is records/customer_data_snapshot_bundle_20260915.json
with open('dataset/evidence/records/customer_data_snapshot_bundle_20260915.json', encoding='utf-8') as f:
    data = json.load(f)

print("exported_at:", data.get('exported_at'))
print("source:", data.get('source'))
print()

for snap in data.get('snapshots', []):
    ds = snap.get('data_store')
    coll = snap.get('collection')
    recs = snap.get('records', [])
    print(f"[{ds}] {coll}: {len(recs)} records")
    for r in recs:
        print(f"  {r}")
