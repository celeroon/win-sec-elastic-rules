# User Account Logon Success (Unexpected VirtualAccount)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> If you need to monitor all logon events for managed service accounts and group managed service accounts, monitor for events with "Virtual Account"="Yes".

> A Virtual Account determines if the active account is either a Managed Service Account (MSA) or a Group Managed Service Account (gMSA). MSAs are specialized local accounts intended for service use. The operating system automatically handles their password management, typically updating passwords every 30 days by default. Conversely, gMSAs serve a similar function as MSAs but are configured as domain accounts, allowing for broader service account management within a networked environment.

> [!IMPORTANT]
> Create your own list of virtual accounts to exclude.

<div align="center">
    <img alt="User Account Logon Success (Unexpected VirtualAccount)" src="/logs/Account-Logon/User-Account-Logon-Success/Unexpected-VirtualAccount/img/Unexpected-VirtualAccount.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\Account-Logon\User-Account-Logon-Success\Unexpected-VirtualAccount\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: "4624" AND winlog.event_data.VirtualAccount: "%%1842" AND NOT winlog.event_data.TargetUserName: (DWM* OR UMFD*)
```

[XML File](/logs/Account-Logon/User-Account-Logon-Success/Unexpected-VirtualAccount/xml/Unexpected-VirtualAccount.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Success/Unexpected-VirtualAccount/ndjson/POC-Unexpected-VirtualAccount.ndjson)