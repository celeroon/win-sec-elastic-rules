# Successfully Created User Account (HomeDrive Field Anomaly)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> Typically, this field should be "<value not set>" or "-" for new local user accounts. Other values might indicate a potential anomaly.

<div align="center">
    <img alt="Successfully Created User Account (HomeDrive Field Anomaly)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/HomeDrive-Field-Anomaly/img/HomeDrive-Field-Anomaly.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\HomeDrive-Field-Anomaly\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query (ECS):

```
event.code: "4720" AND NOT winlog.event_data.HomePath: ("-" OR "%%1793")
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/HomeDrive-Field-Anomaly/xml/HomeDrive-Field-Anomaly.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/HomeDrive-Field-Anomaly/ndjson/POC-HomeDrive-Field-Anomaly.ndjson)