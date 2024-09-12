# Successfully Created User Account (Dont Expire Password Enabled)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> This flag indicates whether a user account's password is set to never expire. By default, this flag should not be enabled for new user accounts created using the “Active Directory Users and Computers” snap-in. 

<div align="center">
    <img alt="Successfully Created User Account (Dont Expire Password Enabled)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/Dont-Expire-Password-Enabled/img/Dont-Expire-Password-Enabled.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch. 

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\Dont-Expire-Password-Enabled\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND winlog.event_data.UserAccountControl: *%%2089*
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/Dont-Expire-Password-Enabled/xml/Dont-Expire-Password-Enabled.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/Dont-Expire-Password-Enabled/ndjson/POC-Dont-Expire-Password-Enabled.ndjson)