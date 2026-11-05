# Understanding Baselines and Audit Policy

High event volume is normal in AD. Users, computers, and services repeatedly request tickets and access resources. Detection depends on identifying behavior that differs from the account's role and the environment's normal patterns.

### Build the Baseline

| Dimension | Questions to ask |
| --- | --- |
| Account | Human, computer, managed service account, or administrator? |
| Source | Expected workstation, application server, or new host? |
| Destination | Usual service or a newly accessed administrative resource? |
| Time | Business hours, scheduled backup, or unexplained activity? |
| Volume | Normal frequency or a sudden burst? |
| Encryption | Expected compatibility requirements or new RC4 activity? |

Accounts ending in `$` commonly represent computers, but managed service accounts can also use that suffix. Do not assume every such account is harmless or exclude them from every detection.

#### Compare account naming patterns

```splunk
index=win EventCode IN (4624,4768,4769)
| eval AccountType=case(isnull(Account_Name),"Missing account",match(Account_Name,"\$$"),"Ends in dollar",true(),"Other account")
| stats count by AccountType, EventCode
```

This adjusted example checks the **suffix**, and keeps missing fields visible. Inspect multivalued `Account_Name` fields and normalize identity fields before using this in production.

### Stack Counting / Long-Tail Analysis

Count values, sort by frequency, and inspect the rare combinations. Rarity is a lead, not a verdict.

```splunk
index=win EventCode=4769 NOT Account_Name="*$"
| stats count by Account_Name
| sort count
```

Repeat with `Client_Address`, `Service_Name`, or `Ticket_Encryption_Type`. A backup account contacting many servers may be normal; the same activity from a marketing workstation is more suspicious.

SPN prefixes such as `cifs/`, `ldap/`, `http/`, and `MSSQLSvc/` describe services. **Do not assume Event 4769's `Service_Name` always contains the full SPN**; Windows version and field extraction can expose the service account name instead. Inspect raw events and enrich with directory data where needed.

### Audit Policy Configuration

Group Policy location:

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies`

| Category / subcategory | Events of interest |
| --- | --- |
| Account Logon / Credential Validation | 4776 |
| Account Logon / Kerberos Authentication Service | 4768, 4771 |
| Account Logon / Kerberos Service Ticket Operations | 4769 |
| Account Management / User Account Management | Account creation, enablement, reset and disablement |
| Account Management / Security Group Management | Group membership changes |
| DS Access / Directory Service Changes | 5136 and related change events |
| Logon/Logoff / Logon | 4624, 4625 |
| Object Access / File Share | 5140 |

Enable the appropriate success/failure auditing for the subcategories and outcomes required. Directory-change logging also needs the relevant **SACL** on audited objects; the policy setting alone does not guarantee events.

#### Verify effective policy

```cmd
auditpol /get /category:*
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

These are read-only checks. Verify on the actual host performing the activity and confirm events are forwarded, parsed, retained, and timestamped correctly. Sysmon has its own installation and filtering configuration; enabling Windows audit policy does not enable Sysmon.

**Important:** No returned events can mean no activity, a wrong time range, missing collection, parsing differences, or absent auditing. Validate visibility before treating silence as a clean result.

Source: [TryHackMe — Monitoring Active Directory, Tasks 5–6](https://tryhackme.com/room/monitoringactivedirectory). Queries and caveats adjusted for reliable interpretation.
