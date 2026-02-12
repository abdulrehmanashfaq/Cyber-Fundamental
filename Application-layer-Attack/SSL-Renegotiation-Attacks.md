## SSL/TLS Renegotiation Attacks

### 1. What is TLS?

TLS (Transport Layer Security) is a cryptographic protocol designed to provide three main things over a computer network:

- **Encryption**: Keeping data private.
- **Integrity**: Ensuring data is not tampered with.
- **Authentication**: Verifying the identity of the parties.

It is the successor to SSL.

When you connect to a website via HTTPS, your browser and the server perform a **TLS Handshake**. This process allows them to agree on encryption settings and establish a secure connection before any actual data (like your login info) is sent.

---

### 2. Steps of the TLS Handshake

- **Client Hello**
  - The client (your browser) sends:
    - Supported TLS versions
    - List of supported cipher suites (encryption algorithms)
    - A `Client Random` number

- **Server Hello**
  - The server responds, choosing:
    - The TLS version
    - A cipher suite from the client’s list
  - The server also sends a `Server Random` number.

- **Certificate Exchange**
  - The server sends its **digital certificate**.
  - This contains:
    - The server’s public key
    - A signature from a Certificate Authority (CA) to prove the server’s identity.

- **Key Exchange**
  - The client generates a **Premaster Secret**.
  - It encrypts this with the server’s public key and sends it to the server.
  - Only the server can decrypt this using its **private key**.

- **Session Key Derivation**
  - Both sides now have:
    - Client Random
    - Server Random
    - Premaster Secret
  - They use these to calculate the **Master Secret**.
  - From this, they derive **symmetric session keys** used to encrypt the actual data.

- **Finished**
  - Both sides send an encrypted `Finished` message to verify the handshake was successful.

---

### 3. SSL/TLS Renegotiation Attack

An **SSL/TLS Renegotiation Attack** occurs when an attacker triggers a **new handshake** after the initial secure connection has already been established.

Historically, the protocol did not properly **bind the new handshake to the old one**, leading to two main threats:

#### 3.1 Plaintext Injection (MITM)

Scenario:

- An attacker intercepts your connection and starts their own session with the server.
- They send a partial command, for example:

  ```http
  POST /transfer.php?to=attacker
  ```

- They then trigger a **renegotiation** and forward your original handshake to the server.
- The server **splices** these together.

**Effect**:  
To the server, it appears as if **you** sent the attacker’s command followed by your own authentication cookies.

#### 3.2 Denial of Service (DoS)

As noted, cryptography is CPU-heavy. A handshake requires significantly more processing power from the **server** than from the **client**.

DoS via renegotiation:

- The attacker initiates **thousands of renegotiation requests** over a single connection.
- The server’s CPU becomes pegged at 100% trying to perform RSA/Diffie‑Hellman calculations for each request.
- Legitimate users can no longer connect because the server is overwhelmed.

---

### 4. How to Spot It in a PCAP

When analyzing a capture file (e.g., `SSL_renegotiation_edited.pcapng`), you are looking for **re-handshaking**.

- **Normal Traffic**
  - Handshake occurs once at the start.
  - Followed by application data.
  - Connection is stable.

- **Attack Traffic**
  - Multiple `Client Hello` messages appear mid‑stream.
  - Repeated handshake messages within the same TCP stream.
  - High volume of `Client Key Exchange` packets from one IP.

In Wireshark, you can focus on handshake messages with:

```text
ssl.record.content_type == 22
```

---

### 5. Summary of Indicators

- **Multiple Client Hellos**
  - Seeing type `1 (Client Hello)` multiple times without a TCP Close/Reset.

- **Encrypted Alerts**
  - If a server detects something is wrong, it may send an **encrypted alert** before closing the connection.

- **Resource Exhaustion**
  - If the PCAP shows **increasing response times** from the server (e.g., `Server Hello` taking longer and longer), it can indicate a DoS attempt via renegotiation.


