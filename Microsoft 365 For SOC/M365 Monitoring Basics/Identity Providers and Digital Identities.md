# Identity Providers and Digital Identities

When every application manages its own login, the organization has separate passwords, different security controls, and scattered audit trails. One system may support MFA while another does not. Remote work and SaaS applications make that fragmentation harder to manage.

An **Identity Provider (IdP)** centralizes identity and authentication for connected applications. **Microsoft Entra ID**, formerly Azure Active Directory, is Microsoft's cloud identity platform. It is distinct from on-premises Active Directory Domain Services.

### What Is an Identity?

A digital identity represents an entity through attributes such as an identifier, name, ownership, credentials, and access assignments. It is more than a username and password.

| Identity type | Represents | Examples |
| --- | --- | --- |
| Human | A person | Employee, contractor, guest, customer |
| Workload | Software acting on its own or for a user | Application, service principal, automation, script |
| Device | A registered device | Laptop, phone, managed workstation |

**Context matters:** a server can have a device identity, while a service running on it can have a separate workload identity. Monitor both rather than treating every non-human account as the same category.

### Authentication vs Authorization vs Auditing

| Concept | Question answered | Example |
| --- | --- | --- |
| Authentication | Who or what is requesting access? | Validate credentials or a supported passwordless method |
| Authorization | What can that identity do? | Assign application access or a directory role |
| Auditing | What occurred and who was involved? | Record sign-ins and administrative changes |

An IdP supplies identity and policy decisions, but the application also enforces resource-specific permissions. A successful login does not mean permission to read every mailbox or file.

### IdP and Service Provider

```text
User → application/service provider → identity provider
                                          ↓
                              authenticate and evaluate policy
                                          ↓
                       application receives identity/token context
                                          ↓
                              permitted resource access
```

For example, when an application offers Google sign-in, Google provides the identity and the application consumes it. In a Microsoft 365 tenant, Entra ID provides identity for Exchange Online, SharePoint and other connected services.

### Why Centralize Identity?

- **Central management:** create, change, disable, and review identities from a shared control plane.
- **Single Sign-On (SSO):** reuse an authenticated session across supported applications rather than keeping unrelated passwords everywhere.
- **Consistent controls:** apply MFA, Conditional Access and access restrictions to covered applications and identities.
- **Shared visibility:** correlate authentication activity and identity changes across services.

SSO also concentrates risk: one compromised identity or stolen session can reach several services. Coverage, application integration, exclusions and monitoring still determine how effective central controls are.

Source: [TryHackMe — M365 Monitoring Basics, Task 2](https://tryhackme.com/room/m365monitoringbasics). Rewritten study notes; device/workload and authorization distinctions added for clarity.
