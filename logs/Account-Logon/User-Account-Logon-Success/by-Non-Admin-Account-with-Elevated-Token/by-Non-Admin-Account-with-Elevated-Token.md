# User Account Logon Success (by Non-Admin Account with Elevated Token)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> If you need to monitor all logon events for accounts with administrator privileges, monitor this event with "Elevated Token"="Yes".

> [!IMPORTANT]
> Create your own list of administrators to exclude.

<div align="center">
    <img alt="User Account Logon Success (by Non-Admin Account with Elevated Token)" src="/logs/Account-Logon/User-Account-Logon-Success/by-Non-Admin-Account-with-Elevated-Token/img/by-Non-Admin-Account-with-Elevated-Token.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\Account-Logon\User-Account-Logon-Success\by-Non-Admin-Account-with-Elevated-Token\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: "4624" AND winlog.event_data.ElevatedToken: "%%1842" AND NOT winlog.event_datat.TargetUserName: ("Administrator" OR "Admin")
```

[XML File](/logs/Account-Logon/User-Account-Logon-Success/by-Non-Admin-Account-with-Elevated-Token/xml/by-Non-Admin-Account-with-Elevated-Token.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Success/by-Non-Admin-Account-with-Elevated-Token/ndjson/POC-by-Non-Admin-Account-with-Elevated-Token.ndjson)