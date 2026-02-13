## Playing with Time-To-Live: TTL as an Evasion Tool

Time-To-Live (TTL) is supposed to be a simple safety feature in IP: a counter that prevents packets from looping forever. Attackers can twist this field to sneak around monitoring points or learn about your internal path layout.

---

### 1. How TTL-Based Evasion Works

Think of each router hop as subtracting 1 from the TTL.

- **Crafting low-TTL probes**  
  An attacker deliberately sets very small TTL values (1, 2, 3…) so the packet expires at a specific hop instead of reaching the real destination.

- **Triggering ICMP "time exceeded" replies**  
  When a router drops a packet whose TTL hit zero, it sends back an ICMP Time Exceeded (Type 11) message to the source.

- **Abusing the source IP**  
  If the attacker spoofs an internal source address, those ICMP Time Exceeded messages get delivered **inside** your network. The attacker learns about internal devices and paths while your IDS/IPS may never see the original low‑TTL probe.

Used this way, TTL becomes part network‑mapping trick, part sensor‑evasion technique.

---

### 2. Spotting TTL Games in Wireshark

These tricks are subtle at low volume, but stand out when used during broad scanning.

- **Suspicious TTL values from the internet**  
  Open the IPv4 header and look at `ip.ttl`. External traffic arriving with values like 1–5 is rarely normal and often crafted.

- **Bursts of ICMP Type 11**  
  Lots of `icmp.type == 11` messages originating from your own routers/gateways suggest someone is deliberately burning TTLs along the path.

- **Evasion with successful connections**  
  If you see successful `SYN/ACK` responses from internal services around the same time as odd low‑TTL traffic, it can indicate the attacker is probing paths while still managing to talk to the service via other routes.

---

### 3. Hardening Ideas

- **Drop packets with "too small" TTLs**  
  At the edge, discard inbound packets whose TTL is below a policy threshold (for example, anything < 5–10). Legitimate clients almost never send traffic that low.

- **Compare expected vs. observed TTL**  
  For known partners or segments, you can estimate the normal hop count. A TTL that doesn’t fit that pattern is a signal for deeper inspection.

---

### 4. Handy Filters for TTL Investigations

If you’re reviewing something like `ip_ttl.pcapng`, these display filters help:

| Goal                  | Filter                                                             |
|-----------------------|--------------------------------------------------------------------|
| Find low TTL packets  | `ip.ttl < 10`                                                     |
| Find time‑exceeded    | `icmp.type == 11`                                                 |
| Confirm odd success   | `tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.ttl < 64`         |

