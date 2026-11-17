# SharePoint Scenario Investigation

The fictional scenario concerns a suspicious OneNote file shared by **Emma Lawson**, Head of Customer Relationships, with CEO **Michael** and external contacts. The CEO does not recognize the purported pricing update. Investigate both document distribution and the account's earlier access.

**Dataset:** `index=challenge`, initially All time. This is separate from Task 3's `practice` data. No live lab run or challenge answers are claimed here.

### Questions to Resolve

| Question | Evidence |
| --- | --- |
| When did Michael access it? | File/link use events matched to the exact document |
| Which external identities received access? | Sharing targets and their identities/domains |
| Which external identity used the link? | Relevant link-use record and `CorrelationId` |
| What data was accessed before distribution? | File access/download history for Emma's identity |
| Where did the suspicious sign-in originate? | Entra sign-in IP/location and result |

### Suggested Investigation Order

1. Identify the exact document URL/ID from the reported notification.
2. Find upload or modification activity and establish the affected account.
3. Reconstruct sharing targets, link creation and actual link use.
4. Inspect prior file access/downloads, including the PowerPoint artifact asked about in the exercise.
5. Correlate suspicious service activity with Entra sign-ins and access context.

### Supplementary Timeline Queries

```splunk
index=challenge sourcetype="o365:management:activity" Workload=SharePoint ObjectId="*{SUSPICIOUS_FILE}*"
| table _time, UserId, Operation, TargetUserOrGroupName, ObjectId, ClientIP, CorrelationId
| sort 0 _time
```

```splunk
index=challenge sourcetype="o365:management:activity" Workload=SharePoint UserId="{EMMA_UPN}" Operation IN (FileAccessed,FileDownloaded)
| table _time, Operation, SourceFileName, SourceRelativeUrl, ObjectId, ApplicationDisplayName, ClientIP
| sort 0 _time
```

```splunk
index=challenge sourcetype="azure:aad:signin" userPrincipalName="{EMMA_UPN}"
| table _time, userPrincipalName, appDisplayName, ipAddress, location.city, status.errorCode, correlationId
| sort 0 _time
```

### Evidence Discipline

Keep the specific record demonstrating link use; a link-creation event alone is insufficient. A correlation ID helps identify related activity but does not automatically join unrelated audit and sign-in sources. Treat IP location as an estimate, and distinguish attempted access, successful access and confirmed downstream compromise.

Source: [TryHackMe — SharePoint Online Monitoring, Task 6](https://tryhackme.com/room/sharepointonlinemonitoring). Scenario summarized; queries are supplementary templates for study.
