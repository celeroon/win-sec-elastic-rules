# Successfully Created User Account (SAMAccountName Field Anomaly)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> The SAMAccountName field must contain the user account name. An empty or "-" value may indicate a potential anomaly.

<div align="center">
    <img alt="User Account Logon Success (Old NTLM Version)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/SAMAccountName-Field-Anomaly/img/SAMAccountName-Field-Anomaly.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch. The EVTX log (converted from XML) contains entries with empty SAMAccountName fields ('-' or '%%1793'). This is used to test the detection rule."


```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\SAMAccountName-Field-Anomaly\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: "4720" AND winlog.event_data.SamAccountName: ("-" OR "" OR "%%1793")
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/SAMAccountName-Field-Anomaly/xml/SAMAccountName-Field-Anomaly.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/SAMAccountName-Field-Anomaly/ndjson/POC-SAMAccountName-Field-Anomaly.ndjson)