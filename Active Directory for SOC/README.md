# Active Directory for SOC

Study notes following the five rooms in TryHackMe’s SOC Level 2 Active Directory module. New material is rewritten in the same topic-based format as the existing notes: explanations, event tables, investigation steps, and Splunk queries.

## How to Use These Notes

- Read the rooms in the order below. Introduction/conclusion tasks are represented by each room’s overview rather than separate empty files.
- Replace query placeholders and select the correct host, time range and room-specific index. Field names depend on collection and parsing.
- Course-derived searches and supplementary templates are identified in the notes. None was executed against a running lab during this rebuild.
- Existing diagrams and screenshots are retained. New notes use text flow diagrams; no new lab screenshots or challenge results are claimed.
- Read the credential detection caveats alongside the older credential notes.

## 1. Monitoring Active Directory

[TryHackMe room](https://tryhackme.com/room/monitoringactivedirectory)

- [AD Traffic and Authentication Events](Monitoring%20Active%20Directory/AD%20Traffic%20and%20Authentication%20Events.md)
- [Accounts Groups and Resource Access Events](Monitoring%20Active%20Directory/Accounts%20Groups%20and%20Resource%20Access%20Events.md)
- [Understanding Baselines and Audit Policy](Monitoring%20Active%20Directory/Understanding%20Baselines%20and%20Audit%20Policy.md)

## 2. Detecting AD Initial Access

[TryHackMe room](https://tryhackme.com/room/detectingadinitialaccess)

- [Detecting OWA Credential Attacks](Detecting%20AD%20Initial%20Access/Detecting%20OWA%20Credential%20Attacks.md)
- [Detecting VPN Credential Attacks](Detecting%20AD%20Initial%20Access/Detecting%20VPN%20Credential%20Attacks.md)
- [Detecting Web Shell Deployment](Detecting%20AD%20Initial%20Access/Detecting%20Web%20Shell%20Deployment.md)
- [Understanding IIS and Its Logs](Detecting%20AD%20Initial%20Access/Understanding%20IIS%20and%20Its%20Logs.md)

## 3. Detecting AD Credential Attacks

[TryHackMe room](https://tryhackme.com/room/detectingadcredentialattacks)

- [AS-REP Roasting](Detecting%20AD%20Credential%20Attacks/AS-REP%20Roasting.md)
- [Detecting DCSync](Detecting%20AD%20Credential%20Attacks/Detecting%20DCSync.md)
- [Detecting LSASS Credential Dumping](Detecting%20AD%20Credential%20Attacks/Detecting%20LSASS%20Credential%20Dumping.md)
- [Detecting NTDS.dit Extraction](Detecting%20AD%20Credential%20Attacks/Detecting%20NTDS.dit%20Extraction.md)
- [Detection Caveats and Room Guide](Detecting%20AD%20Credential%20Attacks/Detection%20Caveats%20and%20Room%20Guide.md)
- [Kerberoasting](Detecting%20AD%20Credential%20Attacks/Kerberoasting.md)
- [Understanding how tickets work in AD](Detecting%20AD%20Credential%20Attacks/Understanding%20how%20tickets%20work%20in%20AD.md)

## 4. Detecting AD Lateral Movement

[TryHackMe room](https://tryhackme.com/room/detectingadlateralmovement)

- [Detecting PsExec Lateral Movement](Detecting%20AD%20Lateral%20Movement/Detecting%20PsExec%20Lateral%20Movement.md)
- [Detecting RDP Lateral Movement](Detecting%20AD%20Lateral%20Movement/Detecting%20RDP%20Lateral%20Movement.md)
- [Detecting SMB Lateral Movement](Detecting%20AD%20Lateral%20Movement/Detecting%20SMB%20Lateral%20Movement.md)
- [Discovery and Reconnaissance](Detecting%20AD%20Lateral%20Movement/Discovery%20and%20Reconnaissance)
- [How Lateral Movement Works](Detecting%20AD%20Lateral%20Movement/How%20Lateral%20Movement%20Works.md)

## 5. Detecting AD Post-Exploitation

[TryHackMe room](https://tryhackme.com/room/detectingadpostexploitation)

- [AD Post-Exploitation and Long-Term Persistence](Detecting%20AD%20Post-Exploitation/AD%20Post-Exploitation%20and%20Long-Term%20Persistence.md)
- [Data Destruction](Detecting%20AD%20Post-Exploitation/Data%20Destruction.md)
- [Ransomware Detection 1 - Pre-Encryption](Detecting%20AD%20Post-Exploitation/Ransomware%20Detection%201%20-%20Pre-Encryption.md)
- [Ransomware Detection 2 - Deployment and Execution](Detecting%20AD%20Post-Exploitation/Ransomware%20Detection%202%20-%20Deployment%20and%20Execution.md)

## Investigation Reminders

A detection signal is a reason to investigate. Confirm the account, source, destination, event outcome, and collection coverage before concluding an attack succeeded. Process creation, file creation, authentication, and impact are separate pieces of evidence.

Updated from the signed-in course pages on 5 November 2026. Existing local notes were preserved and extended; this is a reconstruction, not a claim that lost files were recovered.
