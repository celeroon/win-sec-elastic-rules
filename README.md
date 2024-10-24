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
- User Accounts Management
  - Successfully Created User Account
    <!-- - [Successfully Created User Account (Out Of Business Hours)] -->
    - [Successfully Created User Account (SAMAccountName Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/SAMAccountName-Field-Anomaly/SAMAccountName-Field-Anomaly.md)
    - [Successfully Created User Account (UserPrincipalName Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/UserPrincipalName-Field-Anomaly/UserPrincipalName-Field-Anomaly.md)
    - [Successfully Created User Account (HomeDirectory Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/HomeDirectory-Field-Anomaly/HomeDirectory-Field-Anomaly.md)
    - [Successfully Created User Account (HomeDrive Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/HomeDrive-Field-Anomaly/HomeDrive-Field-Anomaly.md)
    - [Successfully Created User Account (ScriptPath Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/ScriptPath-Field-Anomaly/ScriptPath-Field-Anomaly.md)
    - [Successfully Created User Account (ProfilePath Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/ProfilePath-Field-Anomaly/ProfilePath-Field-Anomaly.md)
    - [Successfully Created User Account (UserWorkstation Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/UserWorkstation-Field-Anomaly/UserWorkstation-Field-Anomaly.md)
    - [Successfully Created User Account (AccountExpires Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/AccountExpires-Field-Anomaly/AccountExpires-Field-Anomaly.md)
    - [Successfully Created User Account (PrimaryGroupId Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/PrimaryGroupId-Field-Anomaly/PrimaryGroupId-Field-Anomaly.md)
    - [Successfully Created User Account (AllowedToDelegateTo Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/AllowedToDelegateTo-Field-Anomaly/AllowedToDelegateTo-Field-Anomaly.md)
    - [Successfully Created User Account (OldUacValue Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/OldUacValue-Field-Anomaly/OldUacValue-Field-Anomaly.md)
    - [Successfully Created User Account (SidHistory Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/SidHistory-Field-Anomaly/SidHistory-Field-Anomaly.md)
    - [Successfully Created User Account (LogonHours Field Anomaly)](/logs/User-Accounts-Management/Successfully-Created-User-Account/LogonHours-Field-Anomaly/LogonHours-Field-Anomaly.md)
    - [Successfully Created User Account (Normal Account Disabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Normal-Account-Disabled/Normal-Account-Disabled.md)
    - [Successfully Created User Account (Encrypted Text Password Allowed Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Encrypted-Text-Password-Allowed-Enabled/Encrypted-Text-Password-Allowed-Enabled.md)
    - [Successfully Created User Account (Smartcard Required Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Smartcard-Required-Enabled/Smartcard-Required-Enabled.md)
    - [Successfully Created User Account (Not Delegated Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Not-Delegated-Enabled/Not-Delegated-Enabled.md)
    - [Successfully Created User Account (Use DES Key Only Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Use-DES-Key-Only-Enabled/Use-DES-Key-Only-Enabled.md)
    - [Successfully Created User Account (Don't Require Preauth Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Dont-Require-Preauth-Enabled/Dont-Require-Preauth-Enabled.md)
    - [Successfully Created User Account (Trusted To Authenticate For Delegation Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Trusted-To-Authenticate-For-Delegation-Enabled/Trusted-To-Authenticate-For-Delegation-Enabled.md)
    - [Successfully Created User Account (Server Trust Account Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Server-Trust-Account-Enabled/Server-Trust-Account-Enabled.md)
    - [Successfully Created User Account (Don't Expire Password Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Dont-Expire-Password-Enabled/Dont-Expire-Password-Enabled.md)
    - [Successfully Created User Account (Trusted For Delegation Enabled)](/logs/User-Accounts-Management/Successfully-Created-User-Account/Trusted-For-Delegation-Enabled/Trusted-For-Delegation-Enabled.md)
    - [Successfully Created User Account (By non Admin Account)](/logs/User-Accounts-Management/Successfully-Created-User-Account/By-non-Admin-Account/By-non-Admin-Account.md)
  - Failed User Account Creation
    - [Failed User Account Creation (Access Denied)](/logs/User-Accounts-Management/Failed-User-Account-Creation/Access-Denied/Access-Denied.md)
  - Successfully Deleted User Account
    - [Successfully Deleted User Account (Service/Critical User Account Deleted)](/logs/User-Accounts-Management/Successfully-Deleted-User-Account/Service-Critical-User-Account-Deleted/Service-Critical-User-Account-Deleted.md)
    - [Successfully Deleted User Account (non-Admin Account)](/logs/User-Accounts-Management/Successfully-Deleted-User-Account/non-Admin-Account/non-Admin-Account.md)
    - [Successfully Deleted User Account (Out Of Business Hours)](/logs/User-Accounts-Management/Successfully-Deleted-User-Account/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
  - Failed User Account Deletion
    - [Failed User Account Deletion (Access Denied)](/logs/User-Accounts-Management/Failed-User-Account-Deletion/Access-Denied/Access-Denied.md)
  - Successfully Reset User Account Password
    - [Successfully Reset User Account Password (non-Admin Account)](/logs/User-Accounts-Management/Successfully-Reset-User-Account-Password/non-Admin-Account/non-Admin-Account.md)
    - [Successfully Reset User Account Password (Critical Account)](/logs/User-Accounts-Management/Successfully-Reset-User-Account-Password/Critical-Account/Critical-Account.md)
    - [Successfully Reset User Account Password (Out Of Business Hours)](/logs/User-Accounts-Management/Successfully-Reset-User-Account-Password/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
  - Failed User Account Password Reset
    - [Failed User Account Password Reset (Access Denied)](/logs/User-Accounts-Management/Failed-User-Account-Password-Reset/Access-Denied/Access-Denied.md)
    - [Failed User Account Password Reset (Other)](/logs/User-Accounts-Management/Failed-User-Account-Password-Reset/Other/Other.md)
  - Successfully Changed User Account Password
    - [Successfully Changed User Account Password (Out Of Business Hours)](/logs/User-Accounts-Management/Successfully-Changed-User-Account-Password/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
    - [Successfully Changed User Account Password (Critical Accounts)](/logs/User-Accounts-Management/Successfully-Changed-User-Account-Password/Critical-Accounts/Critical-Accounts.md)
    - [Successfully Changed User Account Password (non-Admin Account)](/logs/User-Accounts-Management/Successfully-Changed-User-Account-Password/non-Admin-Account/non-Admin-Account.md)
  - [Failed User Account Password Change](/logs/User-Accounts-Management/Failed-User-Account-Password-Change/Failed-User-Account-Password-Change.md)
  - User Account Activation
    - [User Account Activation (by non-Admin Account)](/logs/User-Accounts-Management/User-Account-Activation/by-non-Admin-Account/by-non-Admin-Account.md)
    - [User Account Activation (Out Of Business Hours)](/logs/User-Accounts-Management/User-Account-Activation/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
  - User Account Deactivation
    - [User Account Deactivation (non-Admin)](/logs/User-Accounts-Management/User-Account-Deactivation/non-Admin/non-Admin.md)
    - [User Account Deactivation (Out Of Business Hours)](/logs/User-Accounts-Management/User-Account-Deactivation/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
  - User Account Lockout
    - [User Account Lockout (non-SYSTEM Account)](/logs/User-Accounts-Management/User-Account-Lockout/non-SYSTEM-Account/non-SYSTEM-Account.md)
    - [User Account Lockout (Critical Account)](/logs/User-Accounts-Management/User-Account-Lockout/Critical-Account/Critical-Account.md)
    - [User Account Lockout (Out Of Business Hours)](/logs/User-Accounts-Management/User-Account-Lockout/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
  - User Account Unlock
    - [User Account Unlock (by non-Admin Account)](/logs/User-Accounts-Management/User-Account-Unlock/by-non-Admin-Account/by-non-Admin-Account.md)
    - [User Account Unlock (Out Of Business Hours)](/logs/User-Accounts-Management/User-Account-Unlock/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
  - Modifications to User Account
    - [Modifications to User Account (PrimaryGroupID Field Anomaly)](/logs/User-Accounts-Management/Modifications-to-User-Account/PrimaryGroupID-Field-Anomaly/PrimaryGroupID-Field-Anomaly.md)
    - [Modifications to User Account (SidHistory Field Anomaly)](/logs/User-Accounts-Management/Modifications-to-User-Account/SidHistory-Field-Anomaly/SidHistory-Field-Anomaly.md)
    - [Modifications to User Account ('Normal Account' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Normal-Account-Disabled/Normal-Account-Disabled.md)
    - [Modifications to User Account ('Password Not Required' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Password-Not-Required-Enabled/Password-Not-Required-Enabled.md)
    - [Modifications to User Account ('Encrypted Text Password Allowed' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Encrypted-Text-Password-Allowed-Enabled/Encrypted-Text-Password-Allowed-Enabled.md)
    - [Modifications to User Account ('Server Trust Account' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Server-Trust-Account-Enabled/Server-Trust-Account-Enabled.md)
    - [Modifications to User Account ('Don't Expire Password' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Dont-Expire-Password-Enabled/Dont-Expire-Password-Enabled.md)
    - [Modifications to User Account ('Smartcard Required' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Smartcard-Required-Enabled/Smartcard-Required-Enabled.md)
    - [Modifications to User Account ('Password Not Required' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Password-Not-Required-Disabled/Password-Not-Required-Disabled.md)
    - [Modifications to User Account ('Encrypted Text Password Allowed' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Encrypted-Text-Password-Allowed-Disabled/Encrypted-Text-Password-Allowed-Disabled.md)
    - [Modifications to User Account ('Don't Expire Password' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Dont-Expire-Password-Disabled/Dont-Expire-Password-Disabled.md)
    - [Modifications to User Account ('Smartcard Required' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Smartcard-Required-Disabled/Smartcard-Required-Disabled.md)
    - [Modifications to User Account ('Trusted For Delegation' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Trusted-To-Authenticate-For-Delegation-Enabled/Trusted-To-Authenticate-For-Delegation-Enabled.md)
    - [Modifications to User Account ('Trusted For Delegation' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Trusted-For-Delegation-Disabled/Trusted-For-Delegation-Disabled.md)
    - [Modifications to User Account ('Trusted To Authenticate For Delegation' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Trusted-To-Authenticate-For-Delegation-Enabled/Trusted-To-Authenticate-For-Delegation-Enabled.md)
    - [Modifications to User Account ('Trusted To Authenticate For Delegation' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Trusted-To-Authenticate-For-Delegation-Disabled/Trusted-To-Authenticate-For-Delegation-Disabled.md)
    - [Modifications to User Account ('Not Delegated' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Not-Delegated-Enabled/Not-Delegated-Enabled.md)
    - [Modifications to User Account ('Not Delegated' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Not-Delegated-Disabled/Not-Delegated-Disabled.md)
    - [Modifications to User Account ('Use DES Key Only' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Use-DES-Key-Only-Enabled/Use-DES-Key-Only-Enabled.md)
    - [Modifications to User Account ('Don't Require Preauth' – Enabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Dont-Require-Preauth-Enabled/Dont-Require-Preauth-Enabled.md)
    - [Modifications to User Account ('Use DES Key Only' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Use-DES-Key-Only-Disabled/Use-DES-Key-Only-Disabled.md)
    - [Modifications to User Account ('Don't Require Preauth' – Disabled)](/logs/User-Accounts-Management/Modifications-to-User-Account/Dont-Require-Preauth-Disabled/Dont-Require-Preauth-Disabled.md)
    - [Modifications to User Account (Critical Account)](/logs/User-Accounts-Management/Modifications-to-User-Account/Critical-Account/Critical-Account.md)
    - [Modifications to User Account (Out Of Business Hours)](/logs/User-Accounts-Management/Modifications-to-User-Account/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
    - [Modifications to User Account (non-Admin Account)](/logs/User-Accounts-Management/Modifications-to-User-Account/non-Admin-Account/non-Admin-Account.md)
  - [User Account Name Modification](/logs/User-Accounts-Management/User-Account-Name-Modification/User-Account-Name-Modification.md)
  - [Validation of Blank Password Presence](/logs/User-Accounts-Management/Validation-of-Blank-Password-Presence/Validation-of-Blank-Password-Presence.md)
- Security Group Management
  - Successfully Created Security Group
    - [Successfully Created Security Group (Out Of Business Hours)](/logs/Security-Group-Management/Successfully-Created-Security-Group/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
    - [Successfully Created Security Group (non-Admin Account)](/logs/Security-Group-Management/Successfully-Created-Security-Group/non-Admin-Account/non-Admin-Account.md)
  - Failed to Create Security Group
    - [Failed to Create Security Group (Access Denied)](/logs/Security-Group-Management/Failed-to-Create-Security-Group/Access-Denied/Access-Denied.md)
  - Successfully Deleted Security Group
    - [Successfully Deleted Security Group (Out Of Business Hours)](/logs/Security-Group-Management/Successfully-Deleted-Security-Group/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
    - [Successfully Deleted Security Group (non-Admin Account)](/logs/Security-Group-Management/Successfully-Deleted-Security-Group/non-Admin-Account/non-Admin-Account.md)
  - Failed to Delete Security Group
    - [Failed to Delete Security Group (Access Denied)](/logs/Security-Group-Management/Failed-to-Delete-Security-Group/Access-Denied/Access-Denied.md)
  - Successfully Modified Security Group
    - [Successfully Modified Security Group (Out Of Business Hours)](/logs/Security-Group-Management/Successfully-Modified-Security-Group/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
    - [Successfully Modified Security Group (non-Admin Account)](/logs/Security-Group-Management/Successfully-Modified-Security-Group/non-Admin-Account/non-Admin-Account.md)
    - [Successfully Modified Security Group (Critical Groups)](/logs/Security-Group-Management/Successfully-Modified-Security-Group/Critical-Groups/Critical-Groups.md)
  - Failed to Modify Security Group
    - [Failed to Modify Security Group (Access Denied)](/logs/Security-Group-Management/Failed-to-Modify-Security-Group/Access-Denied/Access-Denied.md)
  - Successfully Added to Security Group Membership
    - [Successfully Added to Security Group Membership (Out Of Business Hours)](/logs/Security-Group-Management/Successfully-Added-to-Security-Group-Membership/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
    - [Successfully Added to Security Group Membership (Critical Group)](/logs/Security-Group-Management/Successfully-Added-to-Security-Group-Membership/Critical-Group/Critical-Group.md)
    - [Successfully Added to Security Group Membership (Backup Operators)](/logs/Security-Group-Management/Successfully-Added-to-Security-Group-Membership/Backup-Operators/Backup-Operators.md)
    - [Successfully Added to Security Group Membership (Network Configuration Operators)](/logs/Security-Group-Management/Successfully-Added-to-Security-Group-Membership/Network-Configuration-Operators/Network-Configuration-Operators.md)
    - [Successfully Added to Security Group Membership (Remote Desktop Users)](/logs/Security-Group-Management/Successfully-Added-to-Security-Group-Membership/Remote-Desktop-Users/Remote-Desktop-Users.md)
    - [Successfully Added to Security Group Membership (Remote Management Users)](/logs/Security-Group-Management/Successfully-Added-to-Security-Group-Membership/Remote-Management-Users/Remote-Management-Users.md)
    - [Successfully Added to Security Group Membership (non-Admin Account)](/logs/Security-Group-Management/Successfully-Added-to-Security-Group-Membership/non-Admin-Account/non-Admin-Account.md)
  - Successfully Removed from Security Group Membership
    - [Successfully Removed from Security Group Membership (Out Of Business Hours)](/logs/Security-Group-Management/Successfully-Removed-from-Security-Group-Membership/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
    - [Successfully Removed from Security Group Membership (Critical Group)](/logs/Security-Group-Management/Successfully-Removed-from-Security-Group-Membership/Critical-Group/Critical-Group.md)
    - [Successfully Removed from Security Group Membership (Backup Operators)](/logs/Security-Group-Management/Successfully-Removed-from-Security-Group-Membership/Backup-Operators/Backup-Operators.md)
    - [Successfully Removed from Security Group Membership (Network Configuration Operators)](/logs/Security-Group-Management/Successfully-Removed-from-Security-Group-Membership/Network-Configuration-Operators/Network-Configuration-Operators.md)
    - [Successfully Removed from Security Group Membership (Remote Desktop Users)](/logs/Security-Group-Management/Successfully-Removed-from-Security-Group-Membership/Remote-Desktop-Users/Remote-Desktop-Users.md)
    - [Successfully Removed from Security Group Membership (Remote Management Users)](/logs/Security-Group-Management/Successfully-Removed-from-Security-Group-Membership/Remote-Management-Users/Remote-Management-Users.md)
    - [Successfully Removed from Security Group Membership (non-Admin Account)](/logs/Security-Group-Management/Successfully-Removed-from-Security-Group-Membership/non-Admin-Account/non-Admin-Account.md)
  - [Denied Access to Security Group Membership](/logs/Security-Group-Management/Denied-Access-to-Security-Group-Membership/Access-Denied/Access-Denied.md)
  - Listing of Security Group Memberships
    - [Listing of Security Group Memberships (Out Of Business Hours)](/logs/Security-Group-Management/Listing-of-Security-Group-Memberships/Out-Of-Business-Hours/Out-Of-Business-Hours.md)
    - [Listing of Security Group Memberships (Critical Groups)](/logs/Security-Group-Management/Listing-of-Security-Group-Memberships/Critical-Groups/Critical-Groups.md)
    - [Listing of Security Group Memberships (Suspicious ProcessName/Path)](/logs/Security-Group-Management/Listing-of-Security-Group-Memberships/Suspicious-ProcessName-Path/Suspicious-ProcessName-Path.md)