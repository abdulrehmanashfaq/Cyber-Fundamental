# Entra ID Sign-in Logs

Sign-in logs explain authentication attempts and their context. Use them to identify targeted accounts, failure patterns, a possible successful compromise, and applications reached next.

### Entra Components Behind the Logs

- **Users and sign-ins:** authentication activity and client context.
- **Roles and permissions:** authorization assignments, with changes recorded in audit logs.
- **MFA:** requirements and authentication steps.
- **Conditional Access:** policy evaluation and access controls.
- **Identity Protection:** risk signals that support investigation and risk-based policies.

### Important Fields

| Field | Meaning / investigation use |
| --- | --- |
| `id` | Unique sign-in record identifier |
| `createdDateTime` | Sign-in initiation time in UTC |
| `userPrincipalName`, `userId` | Account name and stable identity identifier |
| `appDisplayName`, `appId` | Client application context |
| `resourceDisplayName`, `resourceId` | Resource being accessed |
| `ipAddress` | Observed client address |
| `clientAppUsed`, `isInteractive` | Client type and interaction context |
| `status.errorCode`, `status.failureReason` | Sign-in result and diagnostic explanation |
| `location.*` | IP-based geographic context |
| `correlationId` | Correlation/troubleshooting context |
| `conditionalAccessStatus` | Overall Conditional Access evaluation status |
| `appliedConditionalAccessPolicies[]` | Individual policies and their results |

Microsoft documents these properties in its [signIn resource reference](https://learn.microsoft.com/en-us/graph/api/resources/signin). A Conditional Access result is separate from the sign-in result; read both. Field availability depends on collection privileges and licensing.

### Important Splunk Queries

The room uses **`index=scenario`**. Select **All time** for its historical practice data; narrow the window once the relevant activity is located.

#### 1. Inspect sign-ins

```splunk
index=scenario sourcetype="azure:aad:signin"
```

#### 2. Summarize failures by account

```splunk
index=scenario sourcetype="azure:aad:signin" "status.errorCode"!=0
| stats count as event_count values(ipAddress) as ip_addresses values(appDisplayName) as applications values(status.errorCode) as errorCodes by userPrincipalName
| sort - event_count
| table applications, userPrincipalName, ip_addresses, errorCodes, event_count
```

The list of values helps scope activity but loses chronological relationships. Return to individual events before deciding which IP accessed which app at a particular time.

#### 3. Find successes from a suspicious source

```splunk
index=scenario sourcetype="azure:aad:signin" "status.errorCode"=0 ipAddress="{SUSPICIOUS_IP}"
| stats values(ipAddress) as ip_addresses values(appDisplayName) as applications by userPrincipalName
| table applications, userPrincipalName, ip_addresses
```

#### 4. Reconstruct the account's timeline — supplementary query

```splunk
index=scenario sourcetype="azure:aad:signin" userPrincipalName="{USER_EMAIL}"
| table _time, createdDateTime, id, correlationId, userPrincipalName, appDisplayName, resourceDisplayName, ipAddress, status.errorCode, status.failureReason, conditionalAccessStatus
| sort 0 _time
```

`sort 0` avoids Splunk's default result limit when sorting; use a bounded investigation window on large datasets.

### Error Codes Used in the Room

| Code | Starting interpretation |
| --- | --- |
| 0 | Successful sign-in |
| 50126 | Invalid credentials |
| 50053 | Lock/blocked sign-in condition; inspect the full failure reason |
| 50074 | Strong authentication requirement not satisfied |
| 50055 | Password expired |

Error codes are diagnostic leads. A nonzero record can represent an intermediate authentication interruption rather than the final outcome of the whole user journey. Read the reason, authentication details and neighboring records.

### Practice Method

Identify the failure source and targeted user; locate the first relevant success; compare location and client; then order subsequent application access. Preserve the raw timestamp as well as Splunk's displayed time, since display timezone affects an exact-time answer.

Source: [TryHackMe — M365 Monitoring Basics, Task 4](https://tryhackme.com/room/m365monitoringbasics). Queries follow the room except the marked timeline template; no live-lab results are claimed.
