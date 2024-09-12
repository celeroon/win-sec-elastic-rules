# Successfully Created User Account (By non Admin Account)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> This event occurs when a new user account is created by an account that does not have administrative privileges. Under typical circumstances, user accounts should only be created by accounts with the necessary administrative permissions.

<div align="center">
    <img alt="Successfully Created User Account (Dont Expire Password Enabled)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/By-non-Admin-Account/img/By-non-Admin-Account.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch. 

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\By-non-Admin-Account\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND NOT winlog.event_data.SubjectUserName: ("Administrator")
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/By-non-Admin-Account/xml/By-non-Admin-Account.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/By-non-Admin-Account/ndjson/POC-By-non-Admin-Account.ndjson)