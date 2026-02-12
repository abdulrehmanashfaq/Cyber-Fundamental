# Windows Event Logging & Security Auditing Notes

## 1. Introduction to Windows Event Logs
Windows Event Logs are the central nervous system of Windows monitoring, acting as a comprehensive repository for recording system, security, and application activities.

* **Purpose**: Comprehensive logging for application errors, security auditing, intrusion detection, and diagnostics.
* **Format**: Logs are stored as **.evtx** files.
* **Access**:
    * **GUI**: Via the **Windows Event Viewer** (requires Administrative privileges).
    * **Programmatic**: Via APIs (e.g., Windows Event Log API).
    * **Offline Analysis**: You can open previously saved `.evtx` files from other machines.

---

## 2. Log Categories
Windows organizes events into specific "Logs" based on their source:

| Log Name | Description |
| :--- | :--- |
| **Application** | Errors and status updates from installed programs and software. |
| **System** | Logs from Windows system components (drivers, boot sequence, etc.). |
| **Security** | Auditing events (logons, file access, privilege use). |
| **Setup** | Events related to the installation of applications and Windows updates. |
| **Forwarded Events** | A central repository for logs collected from *other* computers on the network. |

---

## 3. The Anatomy of an Event
Every log entry (Event) follows a standard structure. Understanding these fields is crucial for parsing data efficiently.

* **Log Name**: The container of the event (e.g., Application).
* **Source**: The software or component that generated the log.
* **Event ID**: A unique numeric identifier defining the specific type of event.
* **Level**: Severity classification (**Information**, **Warning**, **Error**, **Critical**, **Verbose**).
* **User**: The user account associated with the event (often "SYSTEM" or a specific username).
* **XML Data**: The raw, structured format containing all visible fields plus hidden data.

---

## 4. Advanced Analysis Techniques

### A. Filtering with Keywords & XML
* **Keywords**: Use these to filter for broad outcomes (e.g., filtering Security log for "Audit Failure").
* **XML Queries**: Used for granular control via the "Filter Current Log" menu.
    * *Use Case*: Filter by `SubjectLogonId` (e.g., "0x3E7") to track a specific session across multiple events.

### B. Understanding Access Control (SDDL & ACLs)
To understand *why* a security log was generated, you must distinguish between permissions and auditing.
* **DACL (Discretionary Access Control List)**: Defines **Permissions** (Who is allowed/denied?).
* **SACL (System Access Control List)**: Defines **Auditing** (Who gets logged?).
* **NewSd / OldSd**: Found in logs like **Event ID 4907**. These fields show the Security Descriptor in **SDDL** format.

#### Deep Dive: Decoding SDDL Strings
An SDDL string is a text-based representation of security. Example: `S:ARAI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)`

**1. The Header**
* **O:** Owner | **G:** Group | **D:** DACL | **S:** SACL
* **AR/AI**: Indicates if permissions are inherited or required for children.

**2. The ACE (Access Control Entry) Structure**
`([Type];[Flags];[Rights];[ObjectGUID];[InheritGUID];[Account])`



**3. Common Shorthand Codes**
| Code | Type/Permission | Account (Trustee) |
| :--- | :--- | :--- |
| **A / D** | Allow / Deny | **BA**: Built-in Admins |
| **AU** | Audit (SACL only) | **SY**: Local System |
| **GA / FA** | Full Control | **WD**: Everyone (World) |
| **SA / FA** | Success / Failure Audit | **AU**: Authenticated Users |

[Reference: Understanding SDDL Syntax - Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)

### C. Special Logons & Privilege Constants
A **Special Logon (Event 4672)** occurs when a user logs in with administrative "Privilege Constants." Unlike **Permissions** (which apply to objects), **Privileges** apply to the entire system.

#### The "Big 5" Critical Privileges
| Privilege Constant | Security Significance |
| :--- | :--- |
| **SeDebugPrivilege** | Allows memory inspection of any process. Used to steal hashes from `lsass.exe`. |
| **SeImpersonatePrivilege** | Core requirement for "Potato" exploits to escalate from Service to SYSTEM. |
| **SeBackupPrivilege** | Bypasses all DACL permissions to read any file on the disk. |
| **SeTakeOwnershipPrivilege** | Allows a user to become the "Owner" of any object and rewrite its ACLs. |
| **SeLoadDriverPrivilege** | Allows loading kernel-mode drivers (potential rootkits). |

[Reference: Privilege Constants (User Rights) - Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)

---

## 5. Essential Windows Event IDs (Cheat Sheet)

### Windows System Logs
| Event ID | Description | Significance |
| :--- | :--- | :--- |
| **1074** | System Shutdown/Restart | Detects unexpected reboots, revealing malware or unauthorized access. |
| **6005** | Event Log Service Started | Marks system boot-up; used to detect unauthorized reboots. |
| **6006** | Event Log Service Stopped | Typically system shutdown; abnormal occurrences suggest covering illicit activity. |
| **6013** | Windows Uptime | Logged once daily; shorter uptime indicates a reboot and potential intrusion. |
| **7040** | Service Status Change | Indicates startup type change; could be a sign of system tampering. |

### Windows Security Logs
| Event ID | Description | Significance |
| :--- | :--- | :--- |
| **1102** | Audit Log Cleared | **Critical.** Often indicates an attempt to remove evidence of intrusion. |
| **4624** | Successful Logon | Vital for establishing baseline normal user behavior. |
| **4625** | Failed Logon | Multiple failures indicate a brute-force attack in progress. |
| **4648** | Logon with Explicit Creds | Can indicate lateral movement within a network. |
| **4656** | Object Handle Requested | Useful for detecting attempts to access sensitive resources. |
| **4672** | Special Privileges Assigned | Tracks super user login to ensure privileges are not abused. |
| **4698 / 4702** | Scheduled Task Created/Updated | Detects persistence mechanisms used by attackers to run malicious code. |
| **4700 / 4701** | Scheduled Task Enabled/Disabled | Insight into suspicious manipulation of scheduled tasks. |
| **4719** | Audit Policy Changed | **Critical.** Sign of someone trying to hide tracks by disabling auditing. |
| **4738** | User Account Changed | Sign of account takeover or insider threats. |
| **4771 / 4776** | Kerberos/DC Cred Validation Failure | Multiple failures suggest a brute-force attack. |
| **5140 / 5145** | Network Share Access/Check | Identifies unauthorized access or network mapping for future exploits. |
| **5142** | Network Share Added | Unauthorized shares could be used to exfiltrate data. |
| **5157** | WFP Blocked Connection | Identifies blocked malicious traffic on the network. |
| **7045** | Service Installed | Unknown services suggest malware installation for persistence. |

### Microsoft Defender (Antivirus) Logs
| Event ID | Description | Significance |
| :--- | :--- | :--- |
| **1116** | Malware Detected | Logs when Defender finds malware; surge indicates a targeted attack. |
| **1118** | Remediation Started | Process of removing or quarantining detected malware. |
| **1119** | Remediation Succeeded | Confirms identified threats are effectively neutralized. |
| **1120** | Remediation Failed | **High Priority.** Indicates threats persist and need immediate address. |
| **5001** | Real-time Protection Changed | Unauthorized changes suggest attempts to undermine Defender. |

---

## 6. Practice Decoding
**Example 1: Restricted Folder**
`D:(D;;FA;;;WD)(A;;GA;;;BA)`
* **Translation**: Everyone (**WD**) is **Denied** (**D**) all access (**FA**), while Admins (**BA**) are **Allowed** (**A**) Full Control (**GA**).

**Example 2: Audit Monitoring**
`S:(AU;FA;GR;;;WD)`
* **Translation**: Audit (**AU**) Everyone (**WD**) on **Failure** (**FA**) when they try to **Read** (**GR**) the object.

---

## 7. Best Practices for Professionals
1. **Know Your "Normal"**: You cannot spot anomalies if you don't know what normal traffic looks like.
2. **Monitor "Silence"**: The absence of logs or stopped services is as important as the logs themselves.
3. **Correlate**: A single event is rarely enough. Combine data (e.g., *Failed Logon* + *Special Logon*).
