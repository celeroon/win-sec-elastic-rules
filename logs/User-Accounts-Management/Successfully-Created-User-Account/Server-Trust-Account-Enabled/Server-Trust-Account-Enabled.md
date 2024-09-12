# Successfully Created User Account (Server Trust Account Enabled)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> This flag indicates whether an account is designated as a server trust account, a setting that applies only to domain controller (computer) accounts. It should never be enabled for user accounts.

<div align="center">
    <img alt="Successfully Created User Account (Server Trust Account Enabled)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/Server-Trust-Account-Enabled/img/Server-Trust-Account-Enabled.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\Server-Trust-Account-Enabled\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND winlog.event_data.UserAccountControl: *%%2088*
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/Server-Trust-Account-Enabled/xml/Server-Trust-Account-Enabled.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/Server-Trust-Account-Enabled/ndjson/POC-Server-Trust-Account-Enabled.ndjson)