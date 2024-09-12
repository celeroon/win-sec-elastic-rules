# Successfully Created User Account (AccountExpires Field Anomaly)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> For newly created user accounts, the Account Expires field is typically set to <never> (%%1794), indicating that the account does not have a pre-defined expiration. Any value other than <never> may signal an anomaly, potentially due to an unintended configuration or unauthorized modification. This field corresponds to the accountExpires attribute, which can be altered via Active Directory tools or scripts. 

<div align="center">
    <img alt="Successfully Created User Account (AccountExpires Field Anomaly)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/AccountExpires-Field-Anomaly/img/AccountExpires-Field-Anomaly.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch. 

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\AccountExpires-Field-Anomaly\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query (ECS):

```
event.code: 4720 AND NOT winlog.event_data.AccountExpires: ("-" OR "%%1794")
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/AccountExpires-Field-Anomaly/xml/AccountExpires-Field-Anomaly.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/AccountExpires-Field-Anomaly/ndjson/POC-AccountExpires-Field-Anomaly.ndjson)