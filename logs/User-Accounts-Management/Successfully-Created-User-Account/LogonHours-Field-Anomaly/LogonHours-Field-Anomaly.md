# Successfully Created User Account (LogonHours Field Anomaly)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> The LogonHours field specifies the hours during which a user is permitted to log on. For new domain user accounts, this field should always be set to <value not set>. For new local user accounts, it should be set to All (%%1797), allowing logon at any time. Any deviation from these default settings may indicate an anomaly or unauthorized configuration and should be monitored.

<div align="center">
    <img alt="Successfully Created User Account (LogonHours Field Anomaly)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/LogonHours-Field-Anomaly/img/LogonHours-Field-Anomaly.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\LogonHours-Field-Anomaly\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND NOT winlog.event_data.LogonHours: ("%%1797" OR "%%1793")
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/LogonHours-Field-Anomaly/xml/LogonHours-Field-Anomaly.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/LogonHours-Field-Anomaly/ndjson/POC-LogonHours-Field-Anomaly.ndjson)