# Incident Investigation Report: PH-2026-001

## 1. Executive Summary
* **Incident Classification:** True Positive
* **Time of Activity:** 05/12/2026 17:33:23 (Detection) | 21:35:00 (Triage)
* **Verdict:** Phishing / Credential Harvesting Attempt
* **Priority:** High (User Interaction Confirmed)

---

## 2. Incident Analysis
* **Reason for Classification:** The email contains a link to `hrconnex.thm`. The alert indicates this domain is flagged by threat intelligence. The sender address (`onboarding@hrconnex.thm`) uses **typosquatting/domain spoofing** to mimic a legitimate HR portal.
* **Evidence of Impact:** Firewall and Proxy logs confirmed an outbound request to the malicious URL from a local endpoint. Although the proxy blocked the connection, the attempt confirms that the user interacted with the threat (clicked the link).

---

## 3. Affected Entities
* **Recipient/User:** `j.garcia@thetrydaily.thm`
* **Affected Asset:** User Workstation (Endpoint identification required via DHCP/EDR logs).
* **Department:** HR / Onboarding (Targeted Department).

---

## 4. List of Attack Indicators (IoCs)
| Indicator Type | Value |
| :--- | :--- |
| **Sender Email** | `onboarding@hrconnex.thm` |
| **Malicious URL** | `https://hrconnex.thm/onboarding/15400654060/j.garcia` |
| **Subject Line** | `Action Required: Finalize Your Onboarding Profile` |
| **Data Source** | Email Logs / Proxy Logs |

---

## 5. Escalation Details
* **Escalated To:** Level 2 (L2) Security Analyst
* **Reason for Escalation:** User interaction confirmed. There is a potential risk of credential compromise or "drive-by" malware. L2 review is required to perform a deeper forensic check on the endpoint and check for successful session hijacks or cached credential theft.

---

## 6. Recommended Remediation Actions
1.  **Network Containment:** Blacklist the domain `hrconnex.thm` and its associated IP address on the corporate Firewall and Proxy.
2.  **Email Security:** Blacklist the sender `onboarding@hrconnex.thm` on the Email Security Gateway.
3.  **Threat Purge:** Perform a global search across the mail server for this subject line and purge all instances to prevent further user interaction.
4.  **Account Security:** Force an immediate password reset for user `j.garcia`.
5.  **Endpoint Forensics:** Initiate a full EDR scan on the user's workstation to ensure no malicious scripts were executed during the browser session.
6.  **Awareness:** Flag the user for "Just-in-Time" Phishing Awareness training