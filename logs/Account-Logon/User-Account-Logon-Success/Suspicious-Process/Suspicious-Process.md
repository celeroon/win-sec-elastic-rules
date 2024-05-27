# User Account Logon Success (Suspicious Process)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> If you monitor for potentially malicious software, or software that isn't authorized to request logon actions, monitor this event for Process Name.

Typical processes:
* C:\Windows\System32\services.exe
* C:\Windows\System32\lsass.exe
* C:\Windows\System32\svchost.exe
* C:\Windows\System32\winlogon.exe

<div align="center">
    <img alt="User Account Logon Success (Suspicious Process)" src="/logs/Account-Logon/User-Account-Logon-Success/Suspicious-Process/img/Suspicious-Process.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\Account-Logon\User-Account-Logon-Success\Suspicious-Process\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: "4624" AND NOT process.executable: "-" AND NOT process.executable: (/[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][eE][rR][vV][iI][cC][eE][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[lL][sS][aA][sS][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][vV][cC][hH][oO][sS][tT].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[wW][iI][nN][lL][oO][gG][oO][nN].[eE][xX][eE]/) OR NOT winlog.event_data.ProcessName: (/[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][eE][rR][vV][iI][cC][eE][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[lL][sS][aA][sS][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][vV][cC][hH][oO][sS][tT].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[wW][iI][nN][lL][oO][gG][oO][nN].[eE][xX][eE]/) AND NOT winlog.event_data.ProcessName: "-"
```

[XML File](/logs/Account-Logon/User-Account-Logon-Success/Suspicious-Process/xml/Suspicious-Process.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Success/Suspicious-Process/ndjson/POC-4624-Suspicious-Process.ndjson)