event.code: 4656 AND winlog.keywords: "Audit Success" AND winlog.event_data.ObjectServer: "Security" AND winlog.event_data.ObjectType: "Key" AND winlog.event_data.AccessList: *%%1542* AND winlog.event_data.PrivilegeList: "SeSecurityPrivilege" AND (hour_of_day: [* TO 7] OR hour_of_day: [17 TO *])