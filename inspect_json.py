import json

with open(r'dataset/evidence/records/customer_data_snapshot_bundle_20260917.json', encoding='utf-8') as f:
    data = json.load(f)

print('snapshots count:', len(data['snapshots']))
for snap in data['snapshots']:
    recs = snap['records']
    print(f"  data_store={snap['data_store']} collection={snap['collection']} records={len(recs)}")
    if recs:
        print('    sample keys:', list(recs[0].keys()))
