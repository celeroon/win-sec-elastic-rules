# Successfully Created User Account (Dont Require Preauth Enabled)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> This flag indicates whether the user account is exempt from Kerberos preauthentication. By default, this flag should not be enabled for new user accounts created using the “Active Directory Users and Computers” snap-in, as disabling preauthentication can expose the account to brute-force attacks.

<div align="center">
    <img alt="Successfully Created User Account (Dont Require Preauth Enabled)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/Dont-Require-Preauth-Enabled/img/Dont-Require-Preauth-Enabled.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch. 

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\Dont-Require-Preauth-Enabled\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND winlog.event_data.UserAccountControl: *%%2096*
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/Dont-Require-Preauth-Enabled/xml/Dont-Require-Preauth-Enabled.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/Dont-Require-Preauth-Enabled/ndjson/Dont-Require-Preauth-Enabled.ndjson)