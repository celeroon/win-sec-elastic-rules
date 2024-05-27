# User Account Logon Success (Subject is not SYSTEM)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> Because this event is typically triggered by the SYSTEM account, we recommend that you report it whenever "Subject\Security ID" isn't SYSTEM.

<div align="center">
    <img alt="User Account Logon Success (Subject is not SYSTEM)" src="/logs/Account-Logon/User-Account-Logon-Success/Subject-is-not-SYSTEM/img/Subject-is-not-SYSTEM.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Winlogbeat-Bulk-Read.ps1) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source "./logs/Account-Logon/User-Account-Logon-Success/Subject-is-not-SYSTEM/evtx/*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4624 AND NOT winlog.event_data.SubjectUserSid: ("S-1-5-18" OR "S-1-0-0")
```

[XML File](/logs/Account-Logon/User-Account-Logon-Success/Subject-is-not-SYSTEM/xml/Subject-is-not-SYSTEM.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Success/Subject-is-not-SYSTEM/ndjson/POC-Subject-is-not-SYSTEM.ndjson)