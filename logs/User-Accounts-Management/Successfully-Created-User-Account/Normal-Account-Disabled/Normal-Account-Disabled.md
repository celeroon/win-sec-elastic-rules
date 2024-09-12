# Successfully Created User Account (Normal Account Disabled)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> This flag indicates whether a user account is disabled upon creation. For new user accounts created using the “Active Directory Users and Computers” snap-in, this flag should not be enabled by default. If the flag is set, it may indicate an anomaly or unintended configuration that should be monitored and reviewed.

<div align="center">
    <img alt="Successfully Created User Account (Normal Account Disabled)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/Normal-Account-Disabled/img/Normal-Account-Disabled.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\Normal-Account-Disabled\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query (ECS):

```
event.code: 4720 AND winlog.event_data.UserAccountControl: *%%2052*
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/Normal-Account-Disabled/xml/Normal-Account-Disabled.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/Normal-Account-Disabled/ndjson/POC-Normal-Account-Disabled.ndjson)