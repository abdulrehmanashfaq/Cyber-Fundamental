## TCP Traffic Analysis: Protocol Abuse and Reconnaissance

This guide explains how attackers manipulate the fundamental rules of the TCP protocol to map networks and identify vulnerable services.

---

### 1. The Foundation: The Standard 3‑Way Handshake

A legitimate TCP connection follows a strict, predictable sequence to ensure both hosts are ready for data transfer:

1. **SYN (Synchronize)** – The client requests a connection.  
2. **SYN/ACK (Synchronize/Acknowledge)** – The server acknowledges the request and sends its own synchronize signal.  
3. **ACK (Acknowledge)** – The client confirms receipt, and the virtual circuit is established.

---

### 2. Deep Dive: Scanning Mechanics and Behavioral Logic

#### 2.1 SYN Scanning (The Half‑Open Probe)

This is the most common scanning method because it is fast and "stealthy" at the application layer.

- **Logic**: Instead of completing the handshake, the attacker sends a **RST (Reset)** immediately after receiving the **SYN/ACK**.  
- **Why it works**: By sending the RST, the connection is never fully established. Most application-layer logs (like web servers) only record a connection *after* the final ACK is received.  
- **Detection pattern**: Look for a single host sending a high volume of SYN packets followed immediately by RST packets to the same ports.

---

#### 2.2 "Inverse Mapping" Scans (NULL, FIN, and Xmas)

These scans rely on **RFC 793 behavior**, which dictates how a TCP stack must handle packets that do not belong to an active connection.

- **NULL scan**: Sends a packet with **zero flags** set.  
- **FIN scan**: Sends a packet with only the **FIN** flag, as if ending a connection that never started.  
- **Xmas scan**: Sets the **FIN, PSH, and URG** flags simultaneously.

**Diagnostic logic**:

- **If the port is closed**: The target OS is required by protocol rules to send an **RST**.  
- **If the port is open**: The target OS typically ignores the "illegal" packet and sends **no response**.  
- **Stealth benefit**: These scans often bypass older, non-stateful firewalls that are only configured to look for "new connection" SYN packets.

---

#### 2.3 ACK Scanning (Firewall Probing)

Unlike other scans, the ACK scan is not used to find open ports. It is used to map **firewall access control lists (ACLs)**.

- **Strategy**: The attacker sends an **ACK** packet (which normally only follows a SYN/ACK).  
- **Filtered response**: If the attacker receives **no response**, the port is likely protected by a stateful firewall that dropped the "out‑of‑state" packet.  
- **Unfiltered response**: If the target sends an **RST**, the port is "unfiltered," meaning the firewall allowed the packet through, even if the service port itself is closed.

---

### 3. Analyzing Flags for Threat Hunting

When reviewing traffic, look for these red flags that indicate malicious intent:

- **Flag overload**  
  "Spaghetti" traffic, such as the Xmas scan, where flags like PSH and URG are used in ways that serve no functional purpose for the service being hit.

- **Unidirectional RSTs**  
  Seeing thousands of RST packets leaving your server without any successful data transfers preceding them is a sign your server is responding to a massive scan.

- **The one‑to‑many pattern**  
  A single source IP hitting multiple ports on one host (vertical scan) or one port across many hosts (horizontal scan).

---

### 4. Summary Matrix for Security Analysts

| Attack Type   | Flags Used        | Open Port Behavior          | Closed Port Behavior | Primary Goal         |
|--------------|-------------------|-----------------------------|----------------------|----------------------|
| **SYN scan** | SYN               | SYN/ACK (then RST)          | RST                  | Quick recon          |
| **NULL scan**| None              | No response                 | RST                  | OS fingerprinting    |
| **Xmas scan**| FIN, PSH, URG     | No response                 | RST                  | Firewall evasion     |
| **ACK scan** | ACK               | RST                         | RST                  | Map filtered ports   |

---

### 5. Defensive Strategies

1. **Stateful inspection**  
   Use firewalls that track the state of a connection. A stateful firewall will block an ACK or FIN packet if it didn't see the initial SYN.

2. **Ingress filtering**  
   Block all "impossible" packets, such as those with no flags (NULL) or illegal combinations (Xmas) at the network edge.

3. **Rate limiting**  
   Monitor for a high frequency of RST packets leaving your network, as this is a byproduct of being scanned.


