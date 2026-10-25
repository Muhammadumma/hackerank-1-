import csv

email = 'amara-okeke@proton.me'
user_id = 'user_21'
account = 'account_6440'

with open('dataset/system_activity.csv', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

for r in rows:
    det = r.get('details','')
    if email in det or user_id in det or account in det or 'analytics_5335' in det or 'audit_record_3737' in det:
        print(r['activity_id'], '|', r['event_time'], '|', r['event_type'], '|', r['target_system'], '|', r['resource_id'])
        print('  details:', det[:100])

# Also check what resources are in a 120-min window of activity_3661 (2026-09-05T11:01:53Z)
print()
print('=== Activities within 120min of account_6440 deletion ===')
from datetime import datetime, timezone, timedelta
anchor = datetime(2026,9,5,11,1,53, tzinfo=timezone.utc)
window_start = anchor - timedelta(minutes=120)
window_end = anchor + timedelta(minutes=120)
for r in rows:
    if r.get('source_system') == 'deletion_worker':
        try:
            t = datetime.fromisoformat(r['event_time'].replace('Z','+00:00'))
            if window_start <= t <= window_end:
                print(r['activity_id'], '|', r['event_time'], '|', r['event_type'], '|', r['target_system'], '|', r['resource_id'])
        except:
            pass
