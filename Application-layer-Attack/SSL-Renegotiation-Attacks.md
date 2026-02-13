## TLS Renegotiation Attacks: Extra Handshakes, Extra Trouble

This note explains, in my own words, how renegotiation works in TLS and how attackers can abuse it for injection and DoS.

---

### 1. TLS in One Paragraph

Transport Layer Security (TLS) wraps a normal TCP connection in:

- **Encryption** – So outsiders can’t read the data.  
- **Integrity** – So tampering is detectable.  
- **Authentication** – So clients know which server they’re talking to.

The initial **handshake** is where both sides agree on versions, cipher suites, and keys before any sensitive data moves.

---

### 2. Normal Handshake Flow (High Level)

1. **ClientHello** – Client proposes supported TLS versions and cipher suites, plus a random value.  
2. **ServerHello** – Server picks a version and cipher suite, sends its own random.  
3. **Certificate** – Server presents a certificate containing its public key and CA signature.  
4. **Key exchange** – Client sends key material (e.g., premaster secret) encrypted with the server’s key or negotiated via Diffie‑Hellman.  
5. **Key derivation** – Both sides derive shared secrets and session keys from the randoms + premaster.  
6. **Finished messages** – Encrypted verification messages prove both sides arrived at the same keys.

After that, application data flows encrypted.

---

### 3. What Renegotiation Is and Why It Can Be Dangerous

Renegotiation is basically a **second handshake** that happens after a TLS session is already in place. It was originally intended for:

- Upgrading or changing cipher suites mid‑connection.  
- Requesting client certificates after an initial anonymous phase.

Historically, the protocol didn’t always bind the “new” handshake cleanly to the existing state, which opened doors for abuse.

#### 3.1 Plaintext Injection Concept

In a simplified scenario:

- An attacker sits in the middle and holds a connection to the server.  
- They send a partial HTTP request such as:

  ```http
  POST /transfer.php?to=attacker
  ```

- They then cause a renegotiation and splice the victim’s authenticated traffic into the same TLS stream.  

From the server’s perspective, it can look like the authenticated user’s request included the attacker’s injected prefix.

#### 3.2 Renegotiation‑Based DoS

Handshakes are computationally expensive, especially for the server.

- An attacker keeps a TLS connection open and repeatedly requests renegotiation.  
- The server burns CPU on key exchanges again and again.  
- Enough of these can starve resources so legitimate users see timeouts or very slow handshakes.

---

### 4. Recognizing Renegotiation in PCAPs

In a trace like `SSL_renegotiation_edited.pcapng`, compare:

- **Normal session**
  - One cluster of handshake messages at the start.  
  - Then only encrypted application data.

- **Suspicious session**
  - Fresh `ClientHello` messages appearing **mid‑connection**.  
  - Multiple rounds of `ServerHello` / `ClientKeyExchange` within the same TCP stream.  
  - A disproportionate number of handshake records versus application data from a single client.

In Wireshark, focus on handshake records with:

```text
ssl.record.content_type == 22
```

Then follow individual TCP streams to see how often renegotiation happens.

---

### 5. Handy Indicators

- **Repeated ClientHello**  
  Type `1 (Client Hello)` showing up multiple times in one long‑lived connection without a proper close/reset in between.

- **Encrypted alerts followed by teardown**  
  Encrypted alert records before a connection is closed may indicate the server spotted something off.

- **Growing latency**  
  Server‑side responses (e.g., `ServerHello`) taking longer and longer during waves of renegotiation can point to a resource‑exhaustion attempt.

