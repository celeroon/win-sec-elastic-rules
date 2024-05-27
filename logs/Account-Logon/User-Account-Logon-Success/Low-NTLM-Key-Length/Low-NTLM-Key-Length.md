# User Account Logon Success (Low NTLM Key Length)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> If the Authentication Package is NTLM. In this case, monitor for Key Length not equal to 128, because all Windows operating systems starting with Windows 2000 support 128-bit Key Length.

<div align="center">
    <img alt="User Account Logon Success (Low NTLM Key Length)" src="/logs/Account-Logon/User-Account-Logon-Success/Low-NTLM-Key-Length/img/Low-NTLM-Key-Length.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\Account-Logon\User-Account-Logon-Success\Low-NTLM-Key-Length\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: "4624" AND winlog.event_data.AuthenticationPackageName: "NTLM" AND NOT winlog.event_data.KeyLength: "128"
```

[XML File](/logs/Account-Logon/User-Account-Logon-Success/Low-NTLM-Key-Length/xml/Low-NTLM-Key-Length.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Success/Low-NTLM-Key-Length/ndjson/POC-Low-NTLM-Key-Length.ndjson)