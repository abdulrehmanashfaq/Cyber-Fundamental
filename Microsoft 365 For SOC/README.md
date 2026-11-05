# Microsoft 365 for SOC

Detailed study notes for the first two TryHackMe rooms, following the existing topic-based notes style. Concepts are rewritten; the relevant original Splunk screenshots and supporting figures are stored locally beside the notes.

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

## Investigation Conventions

- Basics uses `scenario`; Entra Monitoring uses `task-2` through `task-5`, with `main` in the OAuth example. These are room-specific indexes.
- Use All time to locate historical lab data, then narrow the window. Preserve UTC source time and check Splunk display timezone.
- Course-derived queries are formatted for readability; changed ordering and supplementary examples are labeled. Queries were not executed against a running lab.
- Screenshots are original lesson figures, not newly generated results from a live investigation. Read their captions for context and limitations.
- Authentication result, Conditional Access result, risk assessment, audit-change outcome, and actual resource activity are different evidence.
- Introductory/concluding task themes are integrated into these notes; every substantive teaching task is mapped above.

## Screenshots and Source Tracking

The two relevant Splunk figures are embedded in [M365 Audit Log Investigation](M365%20Monitoring%20Basics/M365%20Audit%20Log%20Investigation.md) and [OAuth Application Abuse](Entra%20ID%20Monitoring/OAuth%20Application%20Abuse.md). Supporting figures cover the access-decision model, app catalogue, policies, risk overview, AiTM and consent. [Image source inventory](IMAGE-SOURCES.md) records their origins.

Prepared from the signed-in course pages on 5 November 2026. No answers were submitted, lab machines started, or tenant configurations changed.
