# User Account Logon Success (Suspicious Source Address)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> If a specific account, such as a service account, should only be used from your internal IP address list (or some other list of IP addresses). In this case, you can monitor for Network Information\Source Network Address and compare the network address with your list of IP addresses.

> [!IMPORTANT]
> Use your list of IP addreeses or subnets

<div align="center">
    <img alt="User Account Logon Success (Suspicious Source Address)" src="/logs/Account-Logon/User-Account-Logon-Success/Suspicious-Source-Address/img/Suspicious-Source-Address.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\Account-Logon\User-Account-Logon-Success\Suspicious-Source-Address\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query (test):

```
event.code: "4624" AND NOT source.ip: ([10.0.0.0 TO 10.255.255.255] OR [169.254.0.0 TO 169.254.255.255] OR [fe80:: TO febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]) AND NOT source.ip: ("::1" OR "127.0.0.1") OR NOT winlog.event_data.IpAddress: ([10.0.0.0 TO 10.255.255.255] OR [169.254.0.0 TO 169.254.255.255] OR [fe80:: TO febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]) AND NOT winlog.event_data.IpAddress: ("::1" OR "127.0.0.1") AND NOT winlog.event_data.IpAddress: "-"
```

Lucene query (ECS):

```
event.code: "4624" AND NOT source.ip: ([10.0.0.0 TO 10.255.255.255] OR [169.254.0.0 TO 169.254.255.255] OR [fe80:: TO febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]) AND NOT source.ip: ("::1" OR "127.0.0.1") AND NOT source.ip: "-"
```

[XML File](/logs/Account-Logon/User-Account-Logon-Success/Suspicious-Source-Address/xml/Suspicious-Source-Address.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Success/Suspicious-Source-Address/ndjson/POC-Suspicious-Source-Address.ndjson)
