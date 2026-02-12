## Forensic Analysis: TCP RST Injection and Hijacking Anomalies

### 1. Concept: The TCP Reset (RST) Attack

A TCP Reset attack is a method used to abruptly terminate a connection between two parties (e.g., a client and a server).  
By injecting a packet with the `RST` flag set, the attacker tricks the targets into thinking the other side has crashed or closed the session.

#### 1.1 Technical Requirements for the Attacker

1. **Spoofed IP**: The packet must appear to come from the trusted partner.  
2. **Matching ports**: The attacker must know the source and destination ports.  
3. **In‑window sequence numbers ($SEQ$)**: The receiver will ignore the reset if the sequence number is not what it expects next.

---

### 2. Detection via Layer 2 (MAC Address Verification)

In a local network, the IP address is easily faked, but the **MAC Address** (hardware address) is harder to hide because it is required for the packet to move through physical switches.

#### 2.1 The "Mismatched MAC" Indicator

If your network logs show that `192.168.10.4` is assigned to an Apple laptop (`aa:aa:aa:aa:aa:aa`), but a reset packet arrives:

- Claiming to be from that IP, **and**
- Carrying a Dell MAC address (`bb:bb:bb:bb:bb:bb`)

…you have confirmed an injection.

---

### 3. The "Unseen Segment" Mystery in Wireshark

When analyzing a capture, you may see the expert info: **`[TCP ACKed unseen segment]`**.  
This is often the "smoking gun" of a sophisticated hijacking attempt.

#### 3.1 How It Happens (The Race Scenario)

1. **Interception**: An attacker (acting as a Man‑in‑the‑Middle) sees a client send a request. They hold or delay that packet.  
2. **Injection**: The attacker quickly sends their own "ghost" packet to the server using the client's identity.  
3. **The server responds**: The server receives the attacker's packet and sends an ACK back.  
4. **The capture conflict**: Wireshark sees the server's ACK, but because the attacker delayed the original client packet, Wireshark hasn't recorded any data that justifies that ACK.  
5. **Result**: Wireshark flags the ACK as being for an **unseen** segment.

---

### 4. Practical Scenario: "Session Kill" / BGP Hijack Style

**Setup**: A workstation (client) is downloading a sensitive file from a server. An attacker is on the same local subnet.

**Action**:

- The attacker wants to kill the download. They use a tool to sniff the current $SEQ$ numbers.  
- The attacker sends: `Src: Server_IP, Dst: Client_IP, Flag: RST`.  
- **Twist**: To ensure the client doesn't try to recover, the attacker also sends a spoofed ACK to the server for data the client hasn't even finished sending yet.

**Forensic evidence**:

- **In Wireshark**:  
  You see the server send an ACK for $SEQ$ 5000. However, looking back in your logs, the last data the client sent was only at $SEQ$ 4000.  
  Wireshark marks the server's packet as **`[TCP ACKed unseen segment]`**.

- **In switch logs**:  
  You see **MAC flapping** alerts. The server's MAC address is jumping between the actual uplink port and the attacker's port.

- **Conclusion**:  
  This wasn't a network glitch. The unseen segment proves a third party moved the sequence numbers forward before the legitimate client could.

---

### 5. Summary Table for Investigators

| Observation                | Meaning                                                                                     |
|---------------------------|---------------------------------------------------------------------------------------------|
| **Unexpected RST packet** | A connection was forcibly closed.                                                          |
| **MAC address mismatch**  | The packet was sent by a different device than the IP owner.                               |
| **ACKed unseen segment**  | The server is responding to data the attacker sent (or the attacker delayed the real data).|
| **MAC flapping**          | The attacker is actively trying to impersonate another device on the switch.               |

---

### 6. Recommended Defenses

- **Dynamic ARP Inspection (DAI)**: Hardens the network so only the "real" MAC can send traffic for an IP.  
- **Port security**: Limits a switch port to a single, authorized MAC address.  
- **Encryption (TLS)**: Makes it nearly impossible for an attacker to see the $SEQ$ numbers needed to craft the reset.  


