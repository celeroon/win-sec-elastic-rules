# Windows Security (built-in) Monitoring and Detection with Elasticsearch

> This is a work in progress; please check back periodically for updates.

# Project Overview

The primary objective of this project is to develop and test existing detection rules using provided samples of Windows Event Logs (.evtx), leveraging Elasticsearch as a Security Information and Event Management (SIEM) solution. This will be achieved through the integration of open-source tools and projects, in conjunction with Microsoft documentation that offers insights into event logs and security monitoring recommendations.
Additionally, custom logs will be generated using open-source tools to serve as a proof of concept, thereby facilitating thorough testing of the detection rules. The ultimate aim is to enhance security monitoring on Windows systems, ensuring a robust and proactive approach to threat detection.

Moreover, the rules and dashboards (coming soon) are designed as proof of concepts for previously described audit policy settings for Windows, based on research - [win-audit-policy-settings](https://github.com/celeroon/win-audit-policy-settings).


# Acknowledgements

I would like to extend my deepest gratitude to the developers and communities behind the open-source tools and software that have been instrumental in the development of this project.

- **[xml2evtx](https://github.com/JPCERTCC/xml2evtx)**: event Log XML to EVTX File Converter;
- **[Winlogbeat-Bulk-Read.ps1](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Winlogbeat-Bulk-Read.ps1)**: PowerShell script for transferring .evtx log files to Elasticsearch using Winlogbeat;
- **[Microsoft Advanced Security Audit Policy Settings for Windows](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings)**: provides detailed auditing of security-relevant events, enhancing monitoring and compliance.
- **[Winlogbeat](https://www.elastic.co/downloads/beats/winlogbeat)**: windows-specific log shipper that efficiently forwards Windows event logs to destinations like Elasticsearch for centralized log analysis;
- **[Elastic Stack](https://www.elastic.co/elastic-stack)**: SIEM solution that enables real-time threat detection and response, leveraging its effectiveness in consolidating data through Elasticsearch. This establishes a robust foundation for advanced security monitoring;
- **[SigmaHQ](https://github.com/SigmaHQ/sigma)**: standardized cybersecurity rules in YAML format, enhancing threat detection across SIEM systems. Utilizing these rules is an integral part of the project;
<!-- - **[Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules)**: detection rules designed for Hayabusa, which will be employed in the project; -->

# Detection Rules Overview

* All detection rules are disabled by default.
* Detection rules' descriptions <!-- and investigation guides--> are generated by GPT-3.5.
* Detection rules are mapped to MITRE ATT&CK.
* The timestamp (@timestamp) field is overridden to the event.created field.

<!-- * Two rule files are created with prefixes PROD-* and TEST-*.
  - PROD-*:
    * Detection rules are tested based on ECS fields (when Elastic Agent is installed).
    * Schedule (runs every) is changed to 1h.
    * Index 'logs-*' is in use.

  - TEST-*:
    * Logs are sent using Winlogbeat, with no ECS translation.
    * Schedule (runs every) is changed to 1m.
    * Index 'winlogbeat-*' is in use."
-->

<!-- references from alerts to dashboards -->

# Scripts and Configuration Files

## extract_ndjson.sh

The `extract_ndjson.sh` script will extract rules in NDJSON format, making them ready for import into Elasticsearch. To use this script, run it in your terminal:

```bash
./extract_ndjson.sh
```

## Winlogbeat Configuration

To set up Winlogbeat, follow these steps:

1. **Download and place Winlogbeat in this directory**:
   Download Winlogbeat from the [official website](https://www.elastic.co/downloads/beats/winlogbeat) and extract it into the project directory.

2. **Update the `winlogbeat\winlogbeat.yml` configuration**:
   Modify the `winlogbeat.yml` file according to your environment.

3. **Update `winlogbeat-evtx.yml`**:
   Ensure the `winlogbeat-evtx.yml` configuration is also updated to match your setup. This file will help in ingesting all archived .evtx logs. An example configuration file `winlogbeat-evtx.yml.example` is provided for reference.

4. **Download the described tools if you need to ingest all archived EVTX logs or rebuild them**:
   Ensure you have all the necessary tools downloaded as mentioned in the acknowledgements section to process and ingest the .evtx logs efficiently.

# Table of Contents

- Account Logon
  - User Account Logon Success
    - [User Account Logon Success (Subject is not SYSTEM)](/logs/Account-Logon/User-Account-Logon-Success/Subject-is-not-SYSTEM/Subject-is-not-SYSTEM.md)
    - [User Account Logon Success (RestrictedAdminMode Disabled)](/logs/Account-Logon/User-Account-Logon-Success/RestrictedAdminMode-Disabled/RestrictedAdminMode-Disabled.md)
    - [User Account Logon Success (by Non-Admin Account with Elevated Token)](/logs/Account-Logon/User-Account-Logon-Success/by-Non-Admin-Account-with-Elevated-Token/by-Non-Admin-Account-with-Elevated-Token.md)
    - [User Account Logon Success (Unexpected VirtualAccount)](/logs/Account-Logon/User-Account-Logon-Success/Unexpected-VirtualAccount/Unexpected-VirtualAccount.md)
    - [User Account Logon Success (Suspicious Source Address)](/logs/Account-Logon/User-Account-Logon-Success/Suspicious-Source-Address/Suspicious-Source-Address.md)
    - [User Account Logon Success (Old NTLM Version)](/logs/Account-Logon/User-Account-Logon-Success/Old-NTLM-Version/Old-NTLM-Version.md)
    - [User Account Logon Success (Low NTLM Key Length)](/logs/Account-Logon/User-Account-Logon-Success/Low-NTLM-Key-Length/Low-NTLM-Key-Length.md)
    - [User Account Logon Success (Suspicious Process)](/logs/Account-Logon/User-Account-Logon-Success/Suspicious-Process/Suspicious-Process.md)
  - [Unsuccessful-User-Account-Logon]
    - [User Account Logon Failure (0xC0000193)](/logs/Account-Logon/User-Account-Logon-Failure/0xC0000193/0xC0000193.md)
    - [User Account Logon Failure (0xC0000072)](/logs/Account-Logon/User-Account-Logon-Failure/0xC0000072/0xC0000072.md)
    - [User Account Logon Failure (0XC000005E)](/logs/Account-Logon/User-Account-Logon-Failure/0xC000005E/0xC000005E.md)
    - [User Account Logon Failure (0xC000006F)](/logs/Account-Logon/User-Account-Logon-Failure/0xC000006F/0xC000006F.md)
    - [User Account Logon Failure (0xC0000070)](/logs/Account-Logon/User-Account-Logon-Failure/0xC0000070/0xC0000070.md)
    - [User Account Logon Failure (0xC000015B)](/logs/Account-Logon/User-Account-Logon-Failure/0xC000015B/0xC000015B.md)
    - [User Account Logon Failure (0XC0000192)](/logs/Account-Logon/User-Account-Logon-Failure/0xC0000192/0xC0000192.md)
    - [User Account Logon Failure (0XC0000413)](/logs/Account-Logon/User-Account-Logon-Failure/0xC0000413/0xC0000413.md)
    - [User Account Logon Failure (Suspicious Process)](/logs/Account-Logon/User-Account-Logon-Failure/Suspicious-Process/Suspicious-Process.md)

<!--    - [User Account Logon Failure (0xC0000234)]() -->
<!--     - [User Account Logon Failure (Brute-Force)](/rules/windows/security/Account-Logon/Unsuccessful-User-Account-Logon/Unsuccessful-User-Account-Logon-Brute-Force/Unsuccessful-User-Account-Logon-Brute-Force.md) -->

