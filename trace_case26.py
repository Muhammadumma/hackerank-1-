import csv, json

with open('dataset/system_activity.csv', newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

for row in rows:
    act = row['activity_id']
    num = int(act.replace('activity_', ''))
    if 3598 <= num <= 3608:
        print(f"{row['activity_id']} | {row['event_time']} | {row['event_type']} | {row['target_system']} | {row['resource_id']} | {row['details']}")
