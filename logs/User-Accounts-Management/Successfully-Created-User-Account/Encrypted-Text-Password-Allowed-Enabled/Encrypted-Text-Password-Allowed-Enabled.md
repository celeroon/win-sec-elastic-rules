# Successfully Created User Account (Encrypted Text Password Allowed Enabled)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> This flag indicates whether an account allows the use of reversible encryption for its password. By default, this flag should not be enabled for new user accounts created using the “Active Directory Users and Computers” snap-in, as it weakens password security. If enabled, it may indicate an anomaly or a security misconfiguration that should be carefully monitored.

<div align="center">
    <img alt="Successfully Created User Account (Encrypted Text Password Allowed Enabled)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/Encrypted-Text-Password-Allowed-Enabled/img/Encrypted-Text-Password-Allowed-Enabled.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch. 

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\Encrypted-Text-Password-Allowed-Enabled\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND winlog.event_data.UserAccountControl: *%%2091*
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/Encrypted-Text-Password-Allowed-Enabled/xml/Encrypted-Text-Password-Allowed-Enabled.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/Encrypted-Text-Password-Allowed-Enabled/ndjson/Encrypted-Text-Password-Allowed-Enabled.ndjson)