# User Account Logon Failure (Suspicious Process)

As per the [Security Monitoring Recommendations](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#security-monitoring-recommendations) from Microsoft:
> If you have a pre-defined "Process Name" for the process reported in this event, monitor all events with "Process Name" not equal to your defined value.

<div align="center">
    <img alt="User Account Logon Failure (Suspicious Process)" src="/logs/Account-Logon/User-Account-Logon-Failure/Suspicious-Process/img/Suspicious-Process.png" width="80%">
</div>

> [!NOTE]
> *Event generated based on [Microsoft documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624) and converted using the [JPCERTCC/xml2evtx](https://github.com/JPCERTCC/xml2evtx) tool.*

## PoC
> [!NOTE]
> Utilize [sbousseaden's](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) script to ingest the .evtx file into Elasticsearch.

```
.\Winlogbeat-Bulk-Read.ps1 -Exe .\winlogbeat\winlogbeat.exe -Source ".\logs\Account-Logon\User-Account-Logon-Failure\Suspicious-Process\evtx\*.evtx" -Config ".\winlogbeat-evtx.yml"
```

Lucene query:

```
event.code: 4625 AND NOT process.executable: "-" AND NOT process.executable: (/[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][eE][rR][vV][iI][cC][eE][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[lL][sS][aA][sS][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][vV][cC][hH][oO][sS][tT].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[wW][iI][nN][lL][oO][gG][oO][nN].[eE][xX][eE]/) OR NOT winlog.event_data.ProcessName: (/[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][eE][rR][vV][iI][cC][eE][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[lL][sS][aA][sS][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][vV][cC][hH][oO][sS][tT].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[wW][iI][nN][lL][oO][gG][oO][nN].[eE][xX][eE]/) AND NOT winlog.event_data.ProcessName: "-"
```

Lucene query (ECS):

```
event.code: 4625 AND NOT process.executable: "-" AND _exists_:process.executable AND NOT process.executable: (/[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][eE][rR][vV][iI][cC][eE][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[lL][sS][aA][sS][sS].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[sS][vV][cC][hH][oO][sS][tT].[eE][xX][eE]/ OR /[cC]:\\[wW][iI][nN][dD][oO][wW][sS]\\[sS][yY][sS][tT][eE][mM]32\\[wW][iI][nN][lL][oO][gG][oO][nN].[eE][xX][eE]/)
```

[XML File](/logs/Account-Logon/User-Account-Logon-Failure/Suspicious-ProcessName-Path/xml/Suspicious-Process.xml)

[NDJSON Detection Rule](/logs/Account-Logon/User-Account-Logon-Failure/Suspicious-Process/ndjson/POC-4625-Suspicious-Process.ndjson)
