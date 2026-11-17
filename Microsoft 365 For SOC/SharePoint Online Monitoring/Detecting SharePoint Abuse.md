# Detecting SharePoint Abuse

SharePoint is also an attack distribution channel. An attacker can upload or modify a document containing phishing instructions/links and share it using a real corporate identity. Recipients may trust the Microsoft-hosted notification and familiar sender context.

The room highlights **OneNote** as a commonly abused format. The risk comes from content and behavior, not the extension alone. Other document formats and modified existing files can be used too.

### Typical Chain

```text
Compromised identity → upload/modify document → share with targets
                                                   ↓
                                   recipient receives trusted notification
                                                   ↓
                                      link/file opened → further lure
```

A genuine Microsoft sharing notification does not guarantee a safe document. Conversely, merely opening a shared document does not prove malware execution or a second account compromise.

### Investigation Searches

These follow the course's hunt structure. Replace `{BADFILE}` with a distinctive filename/path, then narrow to the exact resource/ID. The practice investigation is in `challenge`; the course's generic examples use `m365`.

#### 1. Establish content origin

```splunk
index=challenge Workload=SharePoint Operation IN (FileUploaded,FileCreated,FileModified) ObjectId="*{BADFILE}*"
| table _time, UserId, Operation, ObjectId
| sort 0 _time
```

`FileModified` is included because the attacker may alter an existing trusted document instead of creating one. The earliest visible uploader is an investigation lead, not proof of the original human attacker.

#### 2. Scope sharing recipients

```splunk
index=challenge Workload=SharePoint Operation IN (AddedToSecureLink,SharingSet) ObjectId="*{BADFILE}*"
| table _time, UserId, Operation, TargetUserOrGroupName, ObjectId
| sort 0 _time
```

Also review anonymous-link creation where relevant. Notification recipient, authorized recipient and actual viewer are different evidence categories. Check partner/external domains and whether a group expands the audience.

#### 3. Find known access

```splunk
index=challenge Workload=SharePoint Operation IN (*LinkUsed,FileAccessed) ObjectId="*{BADFILE}*"
| table _time, UserId, Operation, ClientIP, ObjectId, CorrelationId
| sort 0 _time
```

Supplementary affected-identity summary:

```splunk
index=challenge Workload=SharePoint Operation IN (*LinkUsed,FileAccessed) ObjectId="*{BADFILE}*"
| stats values(UserId) as recorded_viewers by ObjectId
```

Anonymous or service-mediated access may not identify a person reliably. Correlate request and link evidence before treating every listed identity as a confirmed victim.

### Response Concepts

Preserve and safely inspect the shared resource, coordinate quarantine/revocation of malicious sharing, contain compromised access, and prioritize outreach to people with evidence of access. Use approved incident communication channels; these notes do not send warnings or contact partners.

### Partner / Supply-Chain Risk

A compromised company can distribute phishing to clients, who may then expose other organizations. Scope internal and external recipients and follow downstream evidence. The course discusses this cascading possibility; sharing itself does not establish that the next organization was compromised.

### Why a Full Timeline Matters

Attackers can modify an existing file, enlist another user to upload/share content, or use another app. Reconstruct upload/modification, sharing, access and identity events together instead of assuming one event name catches every case.

Source: [TryHackMe — SharePoint Online Monitoring, Task 5](https://tryhackme.com/room/sharepointonlinemonitoring). Course-derived hunts adapted to the challenge index; interpretation caveats and summary query added.
