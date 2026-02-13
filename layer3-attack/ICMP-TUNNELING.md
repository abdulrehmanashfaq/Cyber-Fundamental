## ICMP as a Covert Channel

This note explains, in my own words, how attackers abuse ICMP to move data and how to spot that activity in packet captures.

---

### 1. Concept: Hiding Data Inside “Ping”

ICMP was designed for diagnostics (e.g., `ping`) rather than bulk data transfer, but it still has a **payload field**.  
If a firewall is permissive and allows ICMP through, that payload becomes a convenient tunnel:

- Short commands from attacker → victim (C2).
- Small chunks of files or credentials exfiltrated back to the attacker.

The key idea: **wrap real data inside ICMP Echo traffic** so it blends in with “normal” pings.

---

### 2. How ICMP Tunneling Typically Works

An ICMP tunnel tool will usually:

1. Break the data into small pieces.
2. Encode it (often Base64 or a custom scheme).
3. Place the encoded bytes into the ICMP Echo Request payload.
4. Have a counterpart on the other side reconstruct and decode the stream.

From the network’s point of view it just looks like:

- A host pinging another host very frequently.
- ICMP packets that are **much larger** or more regular than normal test pings.

---

### 3. Hunting for ICMP Tunnels in PCAPs

Assume you’re looking at something like `icmp_tunneling.pcapng`. A practical hunting approach:

#### 3.1 Look at Size and Shape of Packets

- **Baseline behaviour**  
  Normal diagnostic pings usually have a small, fixed payload (dozens of bytes).

- **Suspicious patterns**
  - ICMP packets with **unusually large lengths** compared to the rest of the capture.
  - Fragmented ICMP traffic (lots of fragments tied to the same 5‑tuple).
  - A single internal host sending a steady stream of identically sized ICMP requests to one external IP.

#### 3.2 Inspect the Payload Itself

In Wireshark:

1. Apply a simple display filter:

   ```text
   icmp
   ```

2. Sort by the **Length** column and open a few of the biggest packets.
3. Check the **data** section:
   - If you can clearly read text like usernames, hostnames, or commands, it’s likely **cleartext exfiltration**.
   - If the bytes look like structured ASCII (e.g., a long Base64 alphabet string ending in `=`) or completely random, it may be **encoded/encrypted**.

Right‑clicking a suspect packet and using “Follow → ICMP Stream” (if available) can make the sequence of commands or exfiltrated chunks easier to view in order.

---

### 4. Blue-Team Workflow

When reviewing traffic for potential ICMP misuse:

1. **Filter for ICMP traffic only.**
2. **Identify outliers** by size, frequency, and source/destination pairs.
3. **Drill into payload content** for a handful of samples.
4. **Correlate with host context**:
   - Does this host normally talk ICMP to the internet?
   - Does the timing align with known incidents or suspicious processes?

In tight, well‑controlled environments, **any ICMP payload significantly larger than a standard ping** is worth a closer look.

---

### 5. Defensive Measures

- **Restrict ICMP where possible**  
  If your business does not need internet‑bound ICMP, block it at the perimeter or allow it only from specific monitoring systems.

- **Apply Deep Packet Inspection (DPI)**  
  Use security devices that can:
  - Enforce a maximum ICMP payload size.
  - Flag or drop ICMP traffic that contains obviously encoded data patterns.

- **Rate‑limit diagnostic traffic**  
  Limit how many ICMP Echo Requests a single IP can send per second. This does not stop tunneling completely, but it slows down exfiltration and makes abuse more visible in metrics.

