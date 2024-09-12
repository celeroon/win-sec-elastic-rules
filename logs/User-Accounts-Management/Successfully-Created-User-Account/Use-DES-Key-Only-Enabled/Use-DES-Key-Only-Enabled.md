# Successfully Created User Account (Use DES Key Only Enabled)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720#security-monitoring-recommendations) from Microsoft:
> This flag indicates whether the user account is restricted to using only DES encryption keys for Kerberos authentication. By default, this flag should not be enabled for new user accounts created using the “Active Directory Users and Computers” snap-in, as DES is considered weak and outdated encryption.

<div align="center">
    <img alt="Successfully Created User Account (Use DES Key Only Enabled)" src="/logs/User-Accounts-Management/Successfully-Created-User-Account/Use-DES-Key-Only-Enabled/img/Use-DES-Key-Only-Enabled.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\User-Accounts-Management\Successfully-Created-User-Account\Use-DES-Key-Only-Enabled\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4720 AND winlog.event_data.UserAccountControl: *%%2095*
```

[XML File](/logs/User-Accounts-Management/Successfully-Created-User-Account/Use-DES-Key-Only-Enabled/xml/Use-DES-Key-Only-Enabled.xml)

[NDJSON Detection Rule](/logs/User-Accounts-Management/Successfully-Created-User-Account/Use-DES-Key-Only-Enabled/ndjson/POC-Use-DES-Key-Only-Enabled.ndjson)