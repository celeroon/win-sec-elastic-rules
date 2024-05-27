# User Account Logon Success (Old NTLM Version)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> If a particular version of NTLM is always used in your organization. In this case, you can use this event to monitor Package Name (NTLM only), for example, to find events where Package Name (NTLM only) does not equal NTLM V2.

<div align="center">
    <img alt="User Account Logon Success (Old NTLM Version)" src="/logs/Account-Logon/User-Account-Logon-Success/Old-NTLM-Version/img/Old-NTLM-Version.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\Account-Logon\User-Account-Logon-Success\Old-NTLM-Version\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4624 AND winlog.event_data.AuthenticationPackageName: "NTLM" AND NOT winlog.event_data.LmPackageName: "NTLM V2"
```

[XML File](/logs/Account-Logon/User-Account-Logon-Success/Old-NTLM-Version/xml/Old-NTLM-Version.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Success/Old-NTLM-Version/ndjson/POC-Old-NTLM-Version.ndjson)