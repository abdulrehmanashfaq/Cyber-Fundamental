# Microsoft 365 for SOC

Detailed study notes for all five TryHackMe rooms, following the existing topic-based notes style. Concepts are rewritten; the relevant original Splunk screenshots and supporting figures are stored locally beside the notes.

## Study Order

### 1. M365 Monitoring Basics

[Course room](https://tryhackme.com/room/m365monitoringbasics)

| Teaching task | Notes |
| --- | --- |
| 2 | [Identity Providers and Digital Identities](M365%20Monitoring%20Basics/Identity%20Providers%20and%20Digital%20Identities.md) |
| 3 | [Identities as the Target](M365%20Monitoring%20Basics/Identities%20as%20the%20Target.md) |
| 4 | [Entra ID Sign-in Logs](M365%20Monitoring%20Basics/Entra%20ID%20Sign-in%20Logs.md) |
| 5 | [Entra ID Audit Logs](M365%20Monitoring%20Basics/Entra%20ID%20Audit%20Logs.md) |
| 6 | [M365 Services and Unified Audit Logs](M365%20Monitoring%20Basics/M365%20Services%20and%20Unified%20Audit%20Logs.md) |
| 7 | [M365 Audit Log Investigation](M365%20Monitoring%20Basics/M365%20Audit%20Log%20Investigation.md) |

### 2. Entra ID Monitoring

[Course room](https://tryhackme.com/room/entraidmonitoring)

| Teaching task | Notes |
| --- | --- |
| 2 | [Password-Based Attacks](Entra%20ID%20Monitoring/Password-Based%20Attacks.md) |
| 3 | [Conditional Access and Identity Protection](Entra%20ID%20Monitoring/Conditional%20Access%20and%20Identity%20Protection.md) |
| 4 | [MFA Bypass Techniques](Entra%20ID%20Monitoring/MFA%20Bypass%20Techniques.md) |
| 5 | [Privilege Escalation and Persistence](Entra%20ID%20Monitoring/Privilege%20Escalation%20and%20Persistence.md) |
| 6 | [OAuth Application Abuse](Entra%20ID%20Monitoring/OAuth%20Application%20Abuse.md) |

### 3. Exchange Online Monitoring

[Course room](https://tryhackme.com/room/exchangeonlinemonitoring)

| Teaching task | Notes |
| --- | --- |
| 2 | [Exchange Online Overview](Exchange%20Online%20Monitoring/Exchange%20Online%20Overview.md) |
| 3 | [Exchange Online Logging](Exchange%20Online%20Monitoring/Exchange%20Online%20Logging.md) |
| 4 | [Detecting Mailbox Rule Abuse](Exchange%20Online%20Monitoring/Detecting%20Mailbox%20Rule%20Abuse.md) |
| 5 | [Detecting Phishing from a Compromised Mailbox](Exchange%20Online%20Monitoring/Detecting%20Phishing%20from%20a%20Compromised%20Mailbox.md) |
| 6 | [Incident Investigation](Exchange%20Online%20Monitoring/Incident%20Investigation.md) |

### 4. SharePoint Online Monitoring

[Course room](https://tryhackme.com/room/sharepointonlinemonitoring)

| Teaching task | Notes |
| --- | --- |
| 2 | [SharePoint Overview](SharePoint%20Online%20Monitoring/SharePoint%20Overview.md) |
| 3 | [SharePoint Logging and Sharing Events](SharePoint%20Online%20Monitoring/SharePoint%20Logging%20and%20Sharing%20Events.md) |
| 4 | [Detecting Data Exfiltration](SharePoint%20Online%20Monitoring/Detecting%20Data%20Exfiltration.md) |
| 5 | [Detecting SharePoint Abuse](SharePoint%20Online%20Monitoring/Detecting%20SharePoint%20Abuse.md) |
| 6 | [Real-World Scenario Investigation](SharePoint%20Online%20Monitoring/Real-World%20Scenario%20Investigation.md) |

### 5. Microsoft Intune Monitoring

[Course room](https://tryhackme.com/room/msintunemonitoring)

| Teaching task | Notes |
| --- | --- |
| 2 | [What Is Microsoft Intune](Microsoft%20Intune%20Monitoring/What%20Is%20Microsoft%20Intune.md) |
| 3 | [Intune for Security Teams](Microsoft%20Intune%20Monitoring/Intune%20for%20Security%20Teams.md) |
| 4 | [Detecting Remote Wipe Abuse](Microsoft%20Intune%20Monitoring/Detecting%20Remote%20Wipe%20Abuse.md) |
| 5 | [Detecting App and Script Deployment Abuse](Microsoft%20Intune%20Monitoring/Detecting%20App%20and%20Script%20Deployment%20Abuse.md) |
| 6 | [Intune Security Hardening](Microsoft%20Intune%20Monitoring/Intune%20Security%20Hardening.md) |

## Investigation Conventions

- Basics uses `scenario`; Entra Monitoring uses `task-2` through `task-5`, with `main` in the OAuth example. These are room-specific indexes.
- Exchange uses `task4_5` and `task6`; SharePoint uses `practice` and `challenge`; Intune uses `intune` with a custom Graph audit sourcetype. Generic course screenshots may show `index=*` or `m365` instead.
- Use All time to locate historical lab data, then narrow the window. Preserve UTC source time and check Splunk display timezone.
- Course-derived queries are formatted for readability; changed ordering and supplementary examples are labeled. Queries were not executed against a running lab.
- Screenshots are original lesson figures, not newly generated results from a live investigation. Read their captions for context and limitations.
- Authentication result, Conditional Access result, risk assessment, audit-change outcome, and actual resource activity are different evidence.
- Introductory/concluding task themes are integrated into these notes; every substantive teaching task is mapped above.

## Screenshots and Source Tracking

The original two Splunk figures are embedded in [M365 Audit Log Investigation](M365%20Monitoring%20Basics/M365%20Audit%20Log%20Investigation.md) and [OAuth Application Abuse](Entra%20ID%20Monitoring/OAuth%20Application%20Abuse.md). Supporting figures cover the access-decision model, app catalogue, policies, risk overview, AiTM and consent. The remaining rooms add 33 local course figures, including 16 Splunk examples, placed beside the topics they illustrate. [Image source inventory](IMAGE-SOURCES.md) records their origins.

The first two rooms were prepared from the signed-in course pages on 5 November 2026. The remaining three were added on 16 November 2026. No answers were submitted, lab machines started, or tenant configurations changed.
