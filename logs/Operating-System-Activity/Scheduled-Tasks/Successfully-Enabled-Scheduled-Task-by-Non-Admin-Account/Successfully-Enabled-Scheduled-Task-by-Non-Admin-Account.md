event.code: 4700 AND NOT winlog.event_data.SubjectUserSid: ("S-1-5-18" OR "S-1-5-20") AND NOT winlog.event_data.SubjectUserName: ("Administrator" OR "ADMIN_LIST")
