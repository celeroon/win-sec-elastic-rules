# Successfully Created User Account (Trusted To Authenticate For Delegation Enabled)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> This flag indicates whether a user account is trusted to authenticate for delegation, meaning it can present delegated credentials to services on behalf of other accounts. By default, this flag should not be enabled for new user accounts created using the “Active Directory Users and Computers” snap-in, as it grants significant privileges that could be exploited if misconfigured.

<div align="center">
    <img alt="Successfully Created User Account (Trusted To Authenticate For Delegation Enabled)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/Trusted-To-Authenticate-For-Delegation-Enabled/img/Trusted-To-Authenticate-For-Delegation-Enabled.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\Trusted-To-Authenticate-For-Delegation-Enabled\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND winlog.event_data.UserAccountControl: *%%2098*
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/Trusted-To-Authenticate-For-Delegation-Enabled/xml/Trusted-To-Authenticate-For-Delegation-Enabled.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/Trusted-To-Authenticate-For-Delegation-Enabled/ndjson/POC-Trusted-To-Authenticate-For-Delegation-Enabled.ndjson)