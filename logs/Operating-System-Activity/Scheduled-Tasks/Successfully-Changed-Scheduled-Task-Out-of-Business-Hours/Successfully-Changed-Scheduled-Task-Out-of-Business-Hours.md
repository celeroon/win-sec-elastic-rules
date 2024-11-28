event.code: 4702 AND NOT winlog.event_data.SubjectUserSid: ("S-1-5-18" OR "S-1-5-20") AND (hour_of_day: [* TO 7] OR hour_of_day: [17 TO *])
