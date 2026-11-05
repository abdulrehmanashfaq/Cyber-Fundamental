# Privilege Escalation and Persistence

After gaining access, an attacker may expand privileges and create another route back into the tenant. Sign-in logs establish authentication context; **audit logs reveal changes to identities, roles and authentication methods**.

### What to Inspect

| Field | Meaning |
| --- | --- |
| `activityDisplayName` | Recorded action |
| `initiatedBy` | User or application initiating it |
| `targetResources[]` | Affected accounts, roles or other objects |
| `modifiedProperties[]` | Details of a change where provided |
| `result` | Outcome of the operation |

```splunk
index="task-5" sourcetype="azure:aad:audit"
```

### Role Assignments

| Role | Why it matters |
| --- | --- |
| Global Administrator | Broad tenant administration |
| Exchange Administrator | Exchange management capabilities |
| User Administrator | User/group management and permitted password resets |
| Application Administrator | Application and service-principal management |

These are investigation summaries, not complete permission definitions. An Exchange administrative role does not automatically prove someone read all mailbox contents; application and role restrictions still matter.

A new role assignment deserves scrutiny when it occurs outside provisioning workflows, targets a recently suspicious identity, or is initiated by an unusual actor.

```splunk
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add member to role"
| table _time, activityDisplayName, result, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue
| sort 0 _time
```

Inspect the complete target objects to identify the actual role name and recipient. Check application initiators too, rather than assuming every change originates from a user. Role-management workflows may produce additional activity names beyond this room's example.

### Backdoor Accounts

A new user followed by privileged role membership can provide a fallback identity after the original account is remediated.

```splunk
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add user"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval userCreated='targetResources{}.userPrincipalName'
| table _time, activityDisplayName, result, initiator, userCreated
| sort 0 _time
```

Correlate with approved onboarding, the creator's sign-ins, account properties, role/group assignments, and subsequent use. A new user account is not inherently a backdoor.

### Alternate MFA Methods

Registering an attacker-controlled factor can create an additional authentication route. The exact usefulness depends on credentials, policy and existing session access; control of an MFA factor alone does not guarantee access after a password reset.

#### Registration starts — course-derived query

```splunk
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="User started security info registration" loggedByService="Authentication Methods" operationType="Add"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| table _time, activityDisplayName, result, initiator, initiatedBy.user.ipAddress, additionalDetails{}.value
| sort 0 _time
```

**Important:** starting registration is not proof of successful enrollment. Follow completion/change events, result fields, method details and the actual method state where available. Keep `additionalDetails` key/value relationships together when expanding the raw record.

### Practice Investigation Chain

```text
Suspicious sign-in / MFA activity
           ↓
New account → role assignment → authentication-method changes
           ↓
Subsequent account or application use
```

Task 5 continues the MFA investigation in a different index. Identify the new account, exact assigned role and time of the completed method change. Record evidence for each conclusion rather than inferring completion from a start event.

Source: [TryHackMe — Entra ID Monitoring, Task 5](https://tryhackme.com/room/entraidmonitoring). Rewritten notes; result columns and chronological sorting added to the course-derived searches.
