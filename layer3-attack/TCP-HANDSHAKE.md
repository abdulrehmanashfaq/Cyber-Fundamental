## Understanding the TCP Handshake and Scan Techniques

This note starts with the normal three‑way handshake, then looks at how attackers bend those rules for reconnaissance.

---

### 1. Normal Behavior: The 3‑Way Handshake

A clean TCP connection setup looks like this:

1. **SYN** – Client asks to start a conversation.  
2. **SYN/ACK** – Server agrees and acknowledges.  
3. **ACK** – Client confirms, and both sides can now exchange data.

Everything in this document is about spotting traffic that abuses or skips parts of that pattern.

---

### 2. Common Scan Types and What They Do

#### 2.1 SYN Scan (Half‑Open)

- The scanner sends a SYN to a port.  
- If it gets **SYN/ACK** back, it knows the port is listening, and it immediately replies with **RST** instead of completing the handshake.

Why this matters:

- Many application logs only record a connection after the final ACK.  
- From the app’s point of view, nothing ever “really” connected, but the attacker still learned which ports are open.

Network clue:

- A host that sends lots of SYNs and then quickly follows each SYN/ACK with a RST.

---

#### 2.2 NULL, FIN, and Xmas Scans

These rely on how TCP is defined to behave when a packet does **not** belong to an existing connection.

- **NULL scan** – No flags set at all.  
- **FIN scan** – Only FIN is set, as if we’re closing a connection that was never opened.  
- **Xmas scan** – Multiple flags such as FIN, PSH, and URG are all turned on.

The logic:

- **Closed port** → RFC behavior says the OS should send back an RST.  
- **Open port** → Many stacks simply drop these strange packets and send nothing.

So the attacker can infer:

- “RST = closed”  
- “Silence = probably open”

And because no SYN is used, simple firewalls that only watch for new SYNs may miss this activity.

---

#### 2.3 ACK Scan (Firewall Mapping)

The ACK scan is less about open ports and more about **understanding firewall rules**.

- The scanner sends raw ACKs to various ports.  
- A **stateful firewall** that didn’t see a prior SYN often drops these as “out of state,” leading to no reply.  
- If an RST comes back, the packet made it through the filter, even if the service itself is closed.

Interpretation:

- **No response** → The path is likely filtered/stateful for that port.  
- **RST returned** → The firewall is permissive for that traffic (unfiltered), even if nothing is listening.

---

### 3. Flag Patterns to Watch For

When hunting in PCAPs:

- **Odd flag combinations**  
  Traffic with strange mixes like FIN+PSH+URG that don’t make sense for the application often indicates scanning.

- **RST floods from servers**  
  Large waves of RSTs leaving a server with very little real data exchanged usually means the server is answering many probes.

- **Vertical vs. horizontal probing**  
  - One source to many ports on one host → vertical scan.  
  - One source to the same port across many hosts → horizontal scan.

Both tell you the attacker is mapping your environment rather than using a service for its intended purpose.

---

### 4. Quick Summary Table

| Scan Type   | Flags sent        | Open port behavior          | Closed port behavior | Main purpose        |
|------------|-------------------|-----------------------------|----------------------|---------------------|
| SYN        | SYN               | SYN/ACK, then scanner RST   | RST                  | Fast port discovery |
| NULL       | (no flags)        | Usually no response         | RST                  | Fingerprint / evade |
| Xmas       | FIN, PSH, URG     | Usually no response         | RST                  | Firewall evasion    |
| ACK        | ACK               | RST (if path unfiltered)    | RST                  | Find filtered paths |

---

### 5. Defensive Thoughts

1. **Use real stateful firewalls**  
   Devices should track connection state and drop ACK/FIN packets that don’t belong to any known flow.

2. **Block impossible packets at the edge**  
   Filter traffic with illegal or nonsensical flag combinations, which are rarely needed in legitimate use.

3. **Alert on RST storms and scan patterns**  
   Sudden increases in RST volume or clear vertical/horizontal scan patterns are strong early‑warning signs of reconnaissance.

