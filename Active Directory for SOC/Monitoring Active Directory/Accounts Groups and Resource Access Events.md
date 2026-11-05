# Accounts, Groups and Resource Access Events

Authentication tells us who connected. Account and directory events tell us **who changed access**. Distinguish the **subject** performing an action from the **target** account or object being changed.

### Account Lifecycle

| Event ID | Action |
| --- | --- |
| 4720 | User account created |
| 4722 | Account enabled |
| 4724 | Password reset attempted |
| 4725 | Account disabled |
| 4740 | Account locked out |

```splunk
index=win EventCode=4720
| table _time, host, SAM_Account_Name, Subject_Account_Name
| sort _time
```

`SAM_Account_Name` identifies the created account in the room's extraction; `Subject_Account_Name` identifies the actor. A password-reset attempt is not automatically a successful reset—check the event outcome.

### Security Group Membership

| Added event | Removed event | Group scope |
| --- | --- | --- |
| 4728 | 4729 | Global security group |
| 4732 | 4733 | Local / domain-local security group |
| 4756 | 4757 | Universal security group |

```splunk
index=win EventCode IN (4728,4732,4756)
| table _time, host, Member_Account_Name, Group_Name, Subject_Account_Name
| sort _time
```

Focus on privileged groups, the added member, the actor, originating session, timing, and approved change records. Local Administrators changes must also be collected from member machines.

### Directory Changes: Event 5136

Event **5136** records an AD object's attribute modification when the relevant audit policy and object SACL are configured.

| Attribute | Why inspect it? |
| --- | --- |
| `userAccountControl` | Account state and security-related flags |
| `servicePrincipalName` | Service identity changes |
| `scriptPath` | User logon script |
| `member` | Group membership |
| `displayName`, `description`, `title` | Identity metadata and administrative changes |

#### GPO metadata changes

```splunk
index=win EventCode=5136 Class="groupPolicyContainer"
| table _time, Subject_Account_Name, DN, LDAP_Display_Name, Value
| sort _time
```

A GPO has **AD metadata and SYSVOL files**. Event 5136 may show `versionNumber` or `gPCFileSysPath` changes, but not the complete policy setting change. Inspect SYSVOL file modifications and compare policy contents to establish what was changed.

### Logon Types

| Type | Meaning | Typical activity |
| --- | --- | --- |
| 2 | Interactive | Console session |
| 3 | Network | File shares and remote administration |
| 4 | Batch | Scheduled task |
| 5 | Service | Service logon |
| 7 | Unlock | Unlock or relevant reconnect context |
| 8 | NetworkCleartext | Some web authentication workflows |
| 10 | RemoteInteractive | RDP |

```splunk
index=win EventCode=4624
| stats count by Logon_Type
| sort - count
```

Type 3 is often frequent and does not by itself prove lateral movement. Combine the account, source, destination, and follow-up action. File-share Event **5140** adds resource-access context; detailed share checks use **5145** when configured.

### Onboarding Audit Method

1. Find the new account in 4720 and record who created it.
2. Review enablement and group additions around that time.
3. Inspect its first 4768 requests for source addresses.
4. Compare the role and access with the onboarding request.
5. Follow target-host logons and resource access if anything is unexpected.

Source: [TryHackMe — Monitoring Active Directory, Tasks 4 and 7](https://tryhackme.com/room/monitoringactivedirectory). Removal events and selected caveats are supplementary study context.
