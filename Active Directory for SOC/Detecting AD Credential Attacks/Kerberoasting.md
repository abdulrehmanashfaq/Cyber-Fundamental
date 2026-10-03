# Technical Study Guide: Kerberoasting Attack & Detection

## 1. Executive Summary & Attack Concept
**Kerberoasting** is an authenticated post-exploitation technique categorized under **MITRE ATT&CK [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Steal or Forge Kerberos Tickets: Kerberoasting)**. 

In an Active Directory domain, any authenticated domain account (even the lowest-privileged domain user) can query the Key Distribution Center (KDC) and request a **Kerberos Service Ticket (TGS)** for any service registered with a **Service Principal Name (SPN)**. 

Because the KDC encrypts the core part of the Service Ticket using the **NTLM password hash of the account running that service**, an attacker can extract that encrypted ticket and crack it **completely offline**. The attacker never sends cracking attempts to the Domain Controller, meaning **account lockout policies and failed logon alarms (Event 4625) are never triggered**.

```text
                               KERBEROASTING FLOW

 [ Attacker Workstation ]              [ Domain Controller / KDC ]           [ Offline Cracker ]
   (Any Authenticated User)
            │                                      │                                 │
            │ 1. Query LDAP for SPNs               │                                 │
            ├─────────────────────────────────────>│                                 │
            │<─────────────────────────────────────┤                                 │
            │    (Returns accounts with SPNs)      │                                 │
            │                                      │                                 │
            │ 2. TGS-REQ (Request ticket for SPN)  │                                 │
            ├─────────────────────────────────────>│                                 │
            │                                      │                                 │
            │ 3. TGS-REP (Encrypted with svc hash) │                                 │
            │<─────────────────────────────────────┤                                 │
            │                                                                        │
            │ 4. Extract Ticket & Feed Hash                                          │
            ├───────────────────────────────────────────────────────────────────────>│
            │                                                                        │
            │                                              5. Hashcat / John Offline │
            │                                                 Brute-Force Dictionary │
            │                                                 (Cleartext Password)   │
```

---

## 2. Why the Protocol Allows It: The Structural Weakness

Kerberoasting takes advantage of two core design principles of the Kerberos protocol:

1. **Lack of Access Control in the KDC:**
   - When a user asks the KDC for a Service Ticket via `TGS-REQ`, the KDC checks **only** whether the user presents a valid Ticket Granting Ticket (TGT).
   - **The KDC does not check whether the user has permission to use that service.** Access control is strictly enforced later by the target server during the AP Exchange. Therefore, the KDC dutifully generates and encrypts the ticket for any valid requester.
2. **Symmetric Encryption with Account Secrets:**
   - The Service Ticket payload is encrypted using the password hash of the service account associated with the SPN.
   - If that service runs under a standard domain user account (rather than a 128-character machine account), users often choose human-readable, weak, or memorable passwords that are susceptible to dictionary attacks.

---

## 3. High-Level Comparison: Kerberoasting vs. AS-REP Roasting

The diagram below outlines the operational differences between Kerberoasting and AS-REP Roasting:

![Kerberoasting vs AS-REP Roasting Comparison](pic1.svg)

| Feature | Kerberoasting | AS-REP Roasting |
| :--- | :--- | :--- |
| **Exploited Kerberos Stage** | **TGS-REQ / TGS-REP** (Ticket Granting Service) | **AS-REQ / AS-REP** (Authentication Service) |
| **Monitored Event ID** | **Event 4768 / 4769** (Primarily **4769**) | **Event 4768** |
| **Target Entities** | User-managed service accounts with **SPNs** | User accounts with **Pre-Authentication Disabled** |
| **Required Prerequisite** | **Any valid domain account** (standard user) | **Just the target username** (no password required) |
| **Detection Signal** | `Ticket_Encryption_Type = 0x17` (RC4-HMAC) | `Pre_Authentication_Type = 0` |
| **Cracked Material** | Service account password hash | User account password hash |

---

## 4. Step-by-Step Attack Lifecycle

### Step 1: SPN Discovery & Enumeration
An attacker queries Active Directory's LDAP catalog for all user objects where the `servicePrincipalName` attribute is populated.
- **Built-in Windows Utility:**
  ```cmd
  setspn -T corp.local -Q */*
  ```
- **PowerView / PowerShell:**
  ```powershell
  Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname
  ```
- **Impacket (from Linux):**
  ```bash
  GetUserSPNs.py corp.local/jdoe:Password123 -dc-ip 10.0.0.1 -request
  ```

> [!NOTE]
> Accounts ending in `$` (computer/machine accounts) are ignored by attackers because Active Directory automatically generates randomly rotated, 128-character passwords for computer accounts that cannot be cracked offline. Attackers focus exclusively on **user-created service accounts** (e.g., `svc_mssql`, `svc_backup`, `sqlservice`).

### Step 2: Requesting the Service Ticket (TGS)
The attacker requests a service ticket for the identified SPN. By default, attack tools will request the ticket with **RC4-HMAC encryption (`0x17`)** instead of AES (`0x12`), even if the domain supports AES.
- **Why Downgrade to RC4?**
  - RC4-HMAC hashing operates significantly faster on GPUs during offline cracking compared to computationally intensive AES-128/256 hashing algorithms.
- **Example via Rubeus:**
  ```cmd
  Rubeus.exe kerberoast /outfile:hashes.kerberoast
  ```

### Step 3: Extracting Ticket Hashes
Tools extract the encrypted portion of the ticket (Kerberos 5 TGS-REP etype 23) into standard hash formats compatible with offline crackers.
A sample extracted hash starts with:
```text
$krb5tgs$23$*svc_sql*corp.local*mssql/db01.corp.local*$4B72...[Ciphertext]...
```

### Step 4: Offline Cracking
The attacker takes the hash to an external machine equipped with GPUs and runs Hashcat:
```bash
# Hashcat Mode 13100 = Kerberos 5, etype 23, TGS-REP
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```
Once cracked, the attacker possesses the cleartext password of the service account, often gaining access to sensitive databases or administrative privileges across the domain.

---

## 5. SOC Detection Engineering & Log Analysis

On Domain Controllers, ticket requests generate **Windows Event ID 4769**: *A Kerberos service ticket was requested*.

### Key Fields in Event ID 4769:
1. **Target Service Information:**
   - `Service Name`: The SPN name.
   - `Service ID`: The SID of the service account.
   - *Filter Rule:* Exclude service names ending in `$` (normal machine access) and exclude `krbtgt` (normal TGT renewals). Focus on user service accounts.
2. **Ticket Options & Encryption:**
   - `Ticket Encryption Type`: 
     - `0x17` (`RC4-HMAC`) $\rightarrow$ **High-fidelity anomaly** in a modern domain.
     - `0x12` (`AES256-CTS-HMAC-SHA1-96`) $\rightarrow$ Normal baseline (unless mass requests occur).
3. **Requester Information:**
   - `Account Name`: The username requesting the ticket.
   - `Client Address`: The IP address of the workstation making the request.
4. **Status Code:**
   - `0x0`: Success.

### Detection Patterns & Signals:
- **Anomalous RC4 Encryption Requests:** A burst of Event 4769 with `TicketEncryptionType == 0x17` originating from a standard user workstation.
- **High-Volume TGS Request Spikes:** An individual user requesting multiple service tickets across different SPNs within seconds (characteristic of automated tools like Rubeus or GetUserSPNs).
- **Abnormal User-to-Service Mapping:** An account (e.g., HR or Sales employee) requesting tickets for database or domain infrastructure SPNs they have never accessed before.

---

## 6. Detection Queries (SIEM & Threat Hunting)

### Microsoft Sentinel (KQL)
```kql
// Detect anomalous Kerberoasting activity by monitoring RC4 ticket requests
SecurityEvent
| where EventID == 4769
| where Status == "0x0"
| where TicketEncryptionType == "0x17" // RC4-HMAC
| where not(ServiceName endswith "$" or ServiceName == "krbtgt")
| summarize 
    TotalTicketsRequested = count(), 
    DistinctServices = dcount(ServiceName), 
    ServicesList = make_set(ServiceName) 
    by TargetUserName, Computer, IpAddress, bin(TimeGenerated, 5m)
| where DistinctServices >= 3
| order by TotalTicketsRequested desc
```

### Splunk (SPL)
```spl
index=wineventlog EventCode=4769 Status=0x0 Ticket_Encryption_Type="0x17"
NOT (Service_Name="*$" OR Service_Name="krbtgt")
| stats count as ticket_count dc(Service_Name) as distinct_services values(Service_Name) as services by Account_Name, Client_Address
| where distinct_services >= 3
```

### Elastic Security (KQL / EQL)
```eql
any where event.code == "4769" and
  winlog.event_data.Status == "0x0" and
  winlog.event_data.TicketEncryptionType == "0x17" and
  not winlog.event_data.ServiceName: ("*$", "krbtgt")
```

---

## 7. Prevention & Hardening Recommendations

1. **Migrate to Group Managed Service Accounts (gMSA):**
   - gMSAs delegate password management to the Domain Controller, automatically rotating complex 128-character passwords every 30 days. They are impervious to offline dictionary attacks.
2. **Enforce AES Encryption for Kerberos:**
   - Configure Active Directory user accounts to support AES128 and AES256 (`msDS-SupportedEncryptionTypes` attribute set to `24` or `0x18`).
   - Disable RC4 domain-wide where possible.
3. **Use Long, High-Entropy Passphrases:**
   - For legacy service accounts that cannot use gMSA, enforce randomly generated passwords of **25+ characters**.
4. **Least Privilege & Role Separation:**
   - Never add service accounts to sensitive administrative groups (such as `Domain Admins` or `Account Operators`).
5. **Decoy Accounts (Honeypot SPNs):**
   - Create a dummy domain user account with an attractive SPN (e.g., `MSSQLSvc/db-prod.corp.local`), grant it no permissions, and alert immediately on any Event 4769 generated against it.
### Important Sql queries
#### 1. Filtered RC4 TGS Requests Query (Targeting Non-Computer/Non-krbtgt Accounts)

```splunk
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```
#### 2. Triage & Aggregation Query
```splunk
index=* EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address
```
#### 3. Volume-Based Anomaly Detection Query (Catching both RC4 and AES Kerberoasting)
```splunk
index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=5m
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
| where unique_spns > 5
```