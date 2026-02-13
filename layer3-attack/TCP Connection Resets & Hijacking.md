## TCP Connection Resets and Session Hijacking Clues

This section is about recognizing when someone is force‑closing or hijacking TCP sessions by forging packets rather than by using the application normally.

---

### 1. What a Forged RST Looks Like

A normal TCP Reset (RST) is how a host says “I’m done with this connection right now.” Attackers can **inject their own RST** into an existing flow to tear it down unexpectedly.

To succeed, they generally need:

1. **The right IPs** – The forged packet has to pretend to be one of the endpoints.  
2. **Correct ports** – Source and destination ports must match the real connection.  
3. **A believable sequence number** – If the sequence number is outside the receiver’s current window, the RST is ignored.

When all three line up, the victim believes the peer sent a legitimate reset.

---

### 2. Using Layer 2 to Prove It’s Fake

At Layer 3, IP addressing is easy to spoof. At Layer 2, MAC addresses tie packets to specific interfaces.

A classic giveaway:

- Your CMDB or ARP table says `192.168.10.4` belongs to one NIC (e.g., an Apple laptop MAC).  
- You suddenly see RSTs claiming to be from `192.168.10.4` but with a **completely different vendor MAC**.

That mismatch is strong evidence the packet was injected by another host on the LAN.

---

### 3. "ACKed Unseen Segment" in Wireshark

Wireshark’s expert info sometimes shows **`[TCP ACKed unseen segment]`**. This is often the forensic hint that sequence numbers moved in a way your capture didn’t fully see.

One way this can happen:

1. An attacker sits in the path and temporarily holds back a client packet.  
2. They send their own crafted data or control packet to the server using the client’s identity.  
3. The server sends back an ACK that advances the sequence beyond what your capture has seen from the real client.  
4. Wireshark observes the ACK but has no corresponding data segment in its history.

The result: an ACK referencing bytes that, from the sniffer’s point of view, never existed.

---

### 4. Example: Killing a Download

Imagine a user downloading a sensitive file:

- The attacker watches the flow to learn the current sequence numbers.  
- They inject a forged RST from the “server” to the client.  
- To keep the server happy (and out of sync with reality), they may also send spoofed ACKs pretending the client sent or received data that it never did.

In the traces you might see:

- An ACK from the server acknowledging sequence 5000, even though the last client data you captured only reached 4000.  
- Switch logs showing **MAC flapping**, as the attacker occasionally impersonates the server’s MAC on a different port.

Together, this points to active interference rather than a flaky network.

---

### 5. Investigator’s Cheat Sheet

| Symptom                   | Interpretation                                                                              |
|---------------------------|--------------------------------------------------------------------------------------------|
| Unexpected RST            | Someone forced a connection closed outside normal app behavior.                           |
| IP ↔ MAC mismatch         | The packet didn’t come from the real owner of that IP on the local network.              |
| ACKed unseen segment      | The sequence space advanced due to traffic your sniffer never saw (likely injected).     |
| MAC flapping on a port    | A device is trying to impersonate another host at Layer 2.                                |

---

### 6. Hardening Against RST / Hijack Tricks

- **Dynamic ARP Inspection & Port Security**  
  Make it harder for attackers to spoof MACs or move an IP identity between ports without alarms.

- **Prefer encrypted protocols (TLS)**  
  When headers and payloads are encrypted, guessing or tracking valid sequence numbers becomes much more difficult.

- **Monitor control flags at scale**  
  Sudden spikes in RST traffic to critical services can point to active disruption or scanning side‑effects.

