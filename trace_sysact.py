"""
Search system_activity for user_541-related records and understand the deletion batch.
"""
import csv, re

with open('dataset/system_activity.csv', newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

print("Searching for user_541 in details or any resource tied to account_4857...")
for row in rows:
    details = row.get('details', '')
    res_id = row.get('resource_id', '')
    if 'user_541' in details or res_id == 'account_4857':
        print(f"  act={row['activity_id']} time={row['event_time']} type={row['event_type']} src={row['source_system']} tgt={row['target_system']} res={res_id} result={row['reported_result']}")
        print(f"    details: {details}")

print()
# Now search for the batch: find events near activity_3682
act_3682_idx = None
for i, row in enumerate(rows):
    if row['activity_id'] == 'activity_3682':
        act_3682_idx = i
        break

if act_3682_idx is not None:
    print(f"activity_3682 is at index {act_3682_idx}")
    print("Nearby events (+/- 10):")
    for row in rows[max(0, act_3682_idx-5):act_3682_idx+10]:
        print(f"  act={row['activity_id']} type={row['event_type']} res={row['resource_id']} src={row['source_system']} result={row['reported_result']}")
        print(f"    details: {row['details'][:100]}")
