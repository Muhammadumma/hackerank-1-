import csv, json

sys_act = list(csv.DictReader(open('dataset/system_activity.csv', encoding='utf-8')))

# Check case_31: tombstone_440
# Check case_32: tombstone_9178
# Check case_26: support_4715
# Check case_27: support_4707
# Check case_28: support_2351
for test_res in ['tombstone_440', 'tombstone_9178', 'support_4715', 'support_4707', 'support_2351']:
    # find row in sys_act
    matching = [r for r in sys_act if r['resource_id'] == test_res]
    if matching:
        m = matching[0]
        m_act = int(m['activity_id'].replace('activity_',''))
        # find closest preceding DELETE_RECORD on account_service
        preceding = [r for r in sys_act if r['target_system'] == 'account_service' and r['event_type'] == 'DELETE_RECORD' and int(r['activity_id'].replace('activity_','')) < m_act]
        if preceding:
            closest = preceding[-1]
            print(f"{test_res} (act {m_act}) -> closest preceding account: {closest['resource_id']} (act {closest['activity_id']})")
