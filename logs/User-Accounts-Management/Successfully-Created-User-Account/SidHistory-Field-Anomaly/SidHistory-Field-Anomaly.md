# Successfully Created User Account (SidHistory Field Anomaly)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> The SidHistory field contains the Security Identifier (SID) from a previous domain if the user account has been migrated. For newly created local user accounts, this field should always be set to -. Any value other than - indicates that the account may have been migrated from another domain or tampered with and should be monitored for potential security concerns.

<div align="center">
    <img alt="Successfully Created User Account (SidHistory Field Anomaly)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/SidHistory-Field-Anomaly/img/SidHistory-Field-Anomaly.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\SidHistory-Field-Anomaly\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND NOT winlog.event_data.SidHistory: "-"
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/SidHistory-Field-Anomaly/xml/SidHistory-Field-Anomaly.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/SidHistory-Field-Anomaly/ndjson/SidHistory-Field-Anomaly.ndjson)