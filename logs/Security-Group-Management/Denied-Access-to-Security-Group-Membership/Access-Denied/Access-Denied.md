```
event.code: 4656 AND winlog.keywords: "Audit Failure" AND winlog.event_data.ObjectServer: "Security Account Manager" AND winlog.event_data.ObjectType: "SAM_ALIAS" AND winlog.event_data.AccessMask: "0xf" OR winlog.event_data.AccessList: (*%%5424* AND *%%5425* AND *%%5426* AND *%%5427*)
```
