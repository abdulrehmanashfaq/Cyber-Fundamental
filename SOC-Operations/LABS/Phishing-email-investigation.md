# Incident Investigation Report: 8818

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



# Incident Investigation Report: 8817

## 1. Executive Summary
* **Incident Classification:** True Positive
* **Case Status:** Closed (Contained)
* **Time of Activity:** 05/12/2026 17:32:55 (Detection)
* **Verdict:** Phishing / Credential Harvesting Attempt
* **Priority:** Medium (Blocked at Gateway)

---

## 2. Incident Analysis & Rationale
* **Reason for Classification:** * **Typosquatting:** The sender domain `m1crosoftsupport.co` uses a '1' instead of an 'i', a classic sign of a malicious actor mimicking a legitimate brand (Microsoft).
    * **Social Engineering:** The email uses a "Fear, Uncertainty, and Doubt" (FUD) tactic by claiming a login attempt from Nigeria to pressure the user into clicking a malicious link.
* **Evidence of Triage:** Analysis of the link `https://m1crosoftsupport.co/login` confirms it leads to a fake login portal designed to steal user credentials.
* **Firewall/Proxy Status:** Investigation of the network logs confirms that while the email was received, the firewall/proxy successfully prevented any outbound connection attempts to the malicious URL.

---

## 3. Affected Entities
* **Targeted User:** `c.allen@thetrydaily.thm`
* **Affected Systems:** None. The inbound threat was blocked/contained at the email gateway and proxy level.

---

## 4. List of Attack Indicators (IoCs)
| Indicator Type | Value |
| :--- | :--- |
| **Sender Email** | `no-reply@m1crosoftsupport.co` |
| **Malicious URL** | `https://m1crosoftsupport.co/login` |
| **Reported Attacker IP** | `102.89.222.143` (Mentioned in content) |
| **Subject Line** | `Unusual Sign-In Activity on Your Microsoft Account` |

---

## 5. Escalation & Closure
* **Escalation Requirement:** **Yes.** * **Rationale for Escalation:** Even though the firewall blocked the connection, this alert must be escalated to ensure a global "search and purge" is conducted across the organization's mail server to protect other users who may have received the same email.
* **Rationale for Closure:** The incident is marked as closed after confirming that no internal endpoints successfully communicated with the C2 domain and the malicious sender has been blacklisted.

---

## 6. Recommended Remediation Actions
1.  **Blacklist Domain:** Add `m1crosoftsupport.co` to the organization's global blocklist.
2.  **Email Purge:** Use the mail server admin tools to identify and delete this specific email from all employee inboxes.
3.  **User Notification:** Inform `c.allen@thetrydaily.thm` about the blocked attempt and remind them to report similar emails via the "Report Phishing" button.
4.  **Credential Monitoring:** As a precaution, monitor the user's account for any successful logins from unusual geo-locations for the next 24 hours