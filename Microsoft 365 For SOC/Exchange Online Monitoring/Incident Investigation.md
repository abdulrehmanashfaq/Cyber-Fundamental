# Exchange Online Incident Investigation

Task 6 escalates an unfamiliar sign-in involving **Robert Green**, a finance manager at the fictional TechCorp. The scenario states that employees normally use one office network. Use this as the lab's baseline; it is not a universal production assumption.

**Dataset:** `index=task6`. Start with All time, then narrow to the incident window. The notes describe an investigation method; no lab queries were executed during preparation.

### Reconstruct the Chain

```text
Unusual sign-in → mailbox access → rule/forwarding changes
                                          ↓
                                  phishing messages sent
                                          ↓
                                 recipients and replies
```

| Question | Evidence to inspect |
| --- | --- |
| Which city/source authenticated? | Entra sign-in record and result |
| Which rule appeared? | `New-InboxRule` / `Set-InboxRule` parameters |
| Where was mail forwarded? | `Set-Mailbox` forwarding parameters |
| What phishing was sent? | `Send` subject, identity and source |
| Who received or replied? | Message trace and relevant mailbox records |
| Did the source change? | Time-ordered sign-ins and service activity |

### Supplementary Timeline Searches

```splunk
index=task6 sourcetype="azure:aad:signin" userPrincipalName="{ROBERT_UPN}"
| table _time, userPrincipalName, appDisplayName, ipAddress, location.city, status.errorCode, correlationId
| sort 0 _time
```

```splunk
index=task6 sourcetype="o365:management:activity" Workload=Exchange UserId="{ROBERT_UPN}"
| eval sourceIP=coalesce(ClientIP,ClientIPAddress)
| table _time, Operation, UserId, sourceIP, ObjectId, Item.Subject, Parameters
| sort 0 _time
```

```splunk
index=task6 sourcetype="o365:reporting:messagetrace" Subject="{SUSPICIOUS_SUBJECT}"
| table Received, SenderAddress, RecipientAddress, Subject, Status, FromIP
```

Use mailbox-owner/delegate identifiers and raw records as necessary; `UserId` may not capture every way someone interacts with a mailbox.

### Avoid Timeline Errors

`sort - _time` is **newest first**. Use `sort 0 _time` for oldest-to-newest reconstruction. The course's wording calls its descending sort chronological; both orders are time-sorted, but they tell the story in opposite directions.

An unfamiliar login city is not proof of the attacker's physical location. A source change can reflect a VPN, service routing or a different user; correlate context before attributing it. A recipient reply should be established from actual trace/message evidence, not inferred from a matching subject alone.

### Findings to Record

For each conclusion, keep the timestamp, source type, event identifier if available, actor, affected mailbox/resource, relevant parameters and result. Separate observed facts from hypotheses and unresolved logging gaps.

Source: [TryHackMe — Exchange Online Monitoring, Task 6](https://tryhackme.com/room/exchangeonlinemonitoring). Scenario summarized; searches are supplementary study templates.
