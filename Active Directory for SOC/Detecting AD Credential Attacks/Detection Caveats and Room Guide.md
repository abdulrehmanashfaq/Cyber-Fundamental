# Credential Attacks: Detection Caveats and Room Guide

This guide supplements the existing topic notes after reviewing the current TryHackMe room. It preserves the original explanations, diagrams, and queries while clarifying points that could otherwise lead to an incorrect investigation conclusion.

### Room Map

| Task | Topic | Lab index | Main evidence |
| --- | --- | --- | --- |
| 2 | Kerberoasting | `task2` | DC Event 4769, encryption, account/service burst |
| 3 | AS-REP Roasting | `task3` | DC Event 4768, pre-authentication type |
| 4 | LSASS access | `task4` | Endpoint Sysmon 10, process context and call trace |
| 5 | DCSync | `task5` | DC 4662 replication rights, correlated 4624 |
| 6 | NTDS.dit extraction | `task6` | DC process creation and file creation |
| 7 | Investigation challenge | Separate challenge environment | Reconstruct from that environment's events |

Indexes are **room-specific**. `task3` in another room does not refer to the same dataset.

### Kerberoasting

- The crackable material is encrypted ticket data, not a plaintext password hash handed to the requester. Offline password guesses derive candidate keys and test them against that material.
- RC4 service-ticket encryption uses the service account's NT hash as its key; AES uses other password-derived keys. Avoid describing all ticket encryption as NTLM hashing.
- A 4769 request can be suspicious without proving that a ticket was cracked. Offline cracking itself does not generate domain logon-failure events.
- `0x17` is a useful RC4 signal, but AES Kerberoasting is possible. Keep the existing volume-based search and investigate unusual requester-to-service combinations.
- The lab's `unique_spns > 5` threshold is illustrative. Here the distinct count is based on `Service_Name`, which may identify service accounts rather than individual SPNs.
- Tool options, account capabilities, policy and updates influence encryption selection; do not assume a tool always forces an RC4 downgrade successfully.
- `::ffff:10.5.90.1` is an IPv4-mapped IPv6 representation. Normalize addresses before comparing sources across logs.
- Accounts ending in `$` are not universally safe. Exclusion is a noise-reduction choice, not proof that those accounts cannot be targeted or abused.

### AS-REP Roasting

**Important correction to the original authentication-chain language:** the absence of 4769 or 4624 supports a lead but does not prove an attack. A failed application, cached tickets, a short search window, different DCs, or missing endpoint collection can create the same gap.

The crackable part is the AS-REP encrypted reply data protected with the user's password-derived key. The TGT itself is protected with the `krbtgt` key; avoid saying the whole TGT is encrypted with the target user's password.

Use actual `Pre_Authentication_Type=0` or the equivalent parsed representation. A missing field or `-` is **unknown**, not automatic proof of disabled pre-authentication. Check the raw event and account configuration.

The earlier Sentinel anti-join is an illustrative starting point, not a reliable temporal correlation: it matches by user across the whole window and can exclude a candidate because of unrelated earlier activity. A real correlation should enforce event order, a bounded follow-up window, consistent identity/source context, and collection coverage.

Certificate-based Kerberos pre-authentication is another legitimate mechanism; encrypted-timestamp type 2 is not the only valid normal value. MFA at a VPN or web login does not automatically protect all native Kerberos authentication paths.

An exposed configuration warrants investigation and remediation planning, but it does not prove that the account was already compromised. Password changes limit future use of an old recovered password; they do not remove an attacker's saved ciphertext or automatically revoke every existing ticket/session.

### LSASS Credential Dumping

Available secrets depend on the logon method, session state, Windows configuration and protections such as Credential Guard and LSA protection. Do not assume every historical user's hash or ticket remains available to a dump.

Cached domain logon verifiers are primarily in the SECURITY registry hive, rather than being equivalent to live LSASS NT hashes. DCC2 uses PBKDF2-HMAC-SHA1 and is not a reusable NTLM hash for Pass-the-Hash.

Sysmon Event 10 is available only when ProcessAccess collection and filters include the relevant event. Validate effective configuration rather than relying on a blanket statement about default installs. Absence of Event 10 does not rule out credential theft or other evidence sources.

| Signal | What it supports | What it does not prove |
| --- | --- | --- |
| Access mask includes VM_READ | Process received memory-read rights | Credentials were successfully recovered |
| `dbgcore.dll` / `dbghelp.dll` in trace | Debug/minidump-related code path | A particular tool or malicious intent |
| `UNKNOWN` stack frames | Unresolved or potentially unbacked code | Conclusive injection or actor sophistication |
| Domain user in `SourceUser` | Source process's security context | Account compromise without corroboration |
| SYSTEM context | High-privilege process | Legitimate behavior |

Use full paths, signatures, provenance, parentage and baseline together. A valid System32 path can host an injected process; legitimate security tools can also reside elsewhere. Do not blindly allowlist either category.

### DCSync

The existing `user!="*$"` filter is useful for the lab but hides attacks performed through compromised machine accounts. A stronger hunt considers **all replication callers**, compares them with approved replication sources and authorized synchronization services, and investigates non-DC origins.

Event 4662 requires Directory Service Access auditing and the appropriate SACL. Without that, this event-based detection is missing; network and endpoint telemetry may still expose the activity.

Match the 4662 **subject logon ID** to the 4624 **new/target logon ID on the same DC** and within the relevant time context. Inspect raw field extraction if a generic `Logon_ID` is ambiguous. The replication GUID identifies the right used; account/source context determines whether it is authorized.

### NTDS.dit Extraction

Shadow-copy or IFM activity can be legitimate administration. Investigate intent, command arguments, sensitive file destinations, the associated SYSTEM hive, and subsequent staging/transfer.

A process-start command line proves invocation, not successful extraction. Event 11 provides file-write evidence when configured; check that the file is relevant and follow further activity. Extraction is often local, but staging or exfiltration can still create network artifacts.

Security 4688 with command-line auditing can substitute for some process visibility when Sysmon is absent, but its fields and coverage differ. Event 11 requires Sysmon file-creation collection.

Source: [TryHackMe — Detecting AD Credential Attacks, Tasks 2–6](https://tryhackme.com/room/detectingadcredentialattacks). Room review plus supplementary technical clarification; no lab queries were executed during this note rebuild.
