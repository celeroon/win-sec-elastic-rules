# Successful User Account Logon (RestrictedAdminMode Disabled)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> If "Restricted Admin" mode must be used for logons by certain accounts, use this event to monitor logons by "New Logon\Security ID" in relation to "Logon Type"=10 (RemoteInteractive Logon) and "Restricted Admin Mode"="Yes". If "Restricted Admin Mode"="No" for these accounts, trigger an alert.

According to other [sources](https://labs.withsecure.com/publications/undisable):
> The Restricted Admin Mode option prevents the user’s credentials from being transferred and stored in the target host’s memory

<div align="center">
    <img alt="Successful User Account Logon (RestrictedAdminMode Disabled)" src="/logs/Account-Logon/User-Account-Logon-Success/RestrictedAdminMode-Disabled/img/RestrictedAdminMode-Disabled.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\Account-Logon\User-Account-Logon-Success\RestrictedAdminMode-Disabled\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: "4624" AND winlog.event_data.LogonType: "10" AND winlog.event_data.RestrictedAdminMode: "%%1843"
```

[XML File](/logs/Account-Logon/User-Account-Logon-Success/RestrictedAdminMode-Disabled/xml/RestrictedAdminMode-Disabled.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Success/RestrictedAdminMode-Disabled/ndjson/POC-RestrictedAdminMode-Disabled.ndjson)