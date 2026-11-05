# Entra ID Audit Logs

Once authentication is suspicious, investigate what changed in the tenant. Sign-in logs describe access attempts; **Entra audit logs describe identity and administrative changes**.

### Common Post-Compromise Changes

| Activity | Possible attacker objective |
| --- | --- |
| Password reset | Change control of an identity |
| New MFA method or device | Add another route to authentication |
| Role assignment | Expand privileges |
| User attribute change | Alter identity behavior or profile |
| Application registration or permissions | Establish application-based access |

Legitimate administrators perform these actions too. Compare actor, target, timing, result and approved workflows.

### Actor vs Target vs Change

| Field | Question answered |
| --- | --- |
| `activityDisplayName` | What action was recorded? |
| `initiatedBy.user.*` | Which user initiated it? |
| `initiatedBy.app.*` | Which application initiated it? |
| `targetResources[]` | Which objects were affected? |
| `targetResources[].modifiedProperties[]` | Which properties changed, with old/new values where logged? |
| `result` | Did the operation succeed or fail? |

A password-reset service can appear as the initiating application while the affected user appears in `targetResources`. They are not the same identity. Secrets such as passwords are not expected to appear as plaintext old/new values.

### Important Splunk Queries

#### 1. Inspect all audit activity

```splunk
index=scenario sourcetype="azure:aad:audit"
```

#### 2. Changes targeting an identity

```splunk
index=scenario sourcetype="azure:aad:audit" targetResources{}.userPrincipalName="{USER_EMAIL}"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| sort 0 _time
| table _time, initiator, activityDisplayName, result, targetResources{}.userPrincipalName
```

#### 3. Changes initiated by that identity

```splunk
index=scenario sourcetype="azure:aad:audit" initiatedBy.user.userPrincipalName="{USER_EMAIL}"
| sort 0 _time
| table _time, initiatedBy.user.userPrincipalName, activityDisplayName, result, targetResources{}.userPrincipalName
```

The two searches answer different questions: what happened **to** the account, and what the account **did**.

### Inspect Nested Changes Carefully

Expand the raw event to inspect each target and modified property together. Independently listing multiple arrays can obscure which value belongs to which object. If expanding with `spath` and `mvexpand`, expand a target object first, then its properties, preserving the event identifier.

**Supplementary investigation steps:** correlate change time with sign-ins, confirm whether the operation completed, identify the modified object by ID, and check subsequent use of any new access. A registration-start event alone is not proof that an MFA method was successfully added.

Source: [TryHackMe — M365 Monitoring Basics, Task 5](https://tryhackme.com/room/m365monitoringbasics). Rewritten notes; sorting adjusted to chronological order for investigation.
