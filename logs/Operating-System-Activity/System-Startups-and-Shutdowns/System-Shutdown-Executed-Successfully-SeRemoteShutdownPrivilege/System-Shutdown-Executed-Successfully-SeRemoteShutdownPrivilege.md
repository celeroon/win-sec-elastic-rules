event.code: 4674 AND winlog.keywords: "Audit Success" AND winlog.event_data.PrivilegeList: "SeRemoteShutdownPrivilege" AND NOT winlog.event_data.SubjectUserName: ("NOT" OR "ADMIN" OR "LIST")
