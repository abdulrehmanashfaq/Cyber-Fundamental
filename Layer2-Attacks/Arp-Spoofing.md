## ARP Spoofing: Spotting and Stopping Poisoned Caches

This file focuses on the classic ARP spoofing technique used for man‑in‑the‑middle and DoS, plus how to catch it in captures and on a live host.

---

### 1. Quick Refresher: Normal ARP Behaviour

ARP glues IP addresses to MAC addresses on a LAN.

Normal flow:

- **Request (opcode 1)** – A host broadcasts:  
  “Who has `192.168.10.4`? Tell `192.168.10.5`.”

- **Reply (opcode 2)** – The owner of `192.168.10.4` unicasts back:  
  “`192.168.10.4` is at `50:eb:f6:ec:0e:7f`.”

- **Caching** – The requester stores this mapping so it doesn’t have to ask again for every packet.

The key weakness: ARP will happily accept updates without strong authentication.

---

### 2. How Spoofing Breaks It

Attackers abuse that trust by sending **forged ARP replies** (often without any prior request — “gratuitous ARP”).

Typical pattern:

- To the victim: “Gateway IP is at **my** MAC.”  
- To the gateway: “Victim IP is at **my** MAC.”

Results:

- If the attacker forwards traffic → full **MITM** (sniffing, tampering, SSL stripping, DNS spoofing, etc.).  
- If they drop traffic → targeted **DoS** against one or more hosts.

---

### 3. Capturing and Inspecting ARP Traffic

#### 3.1 Grab a Sample with tcpdump

```bash
# Install tcpdump if needed
sudo apt install tcpdump -y

# Capture ARP traffic on eth0
sudo tcpdump -i eth0 arp -w ARP_Spoof.pcapng
```

#### 3.2 Red Flags in Wireshark

Open `ARP_Spoof.pcapng` and use filters like:

| Goal                  | Wireshark filter                                      |
|-----------------------|-------------------------------------------------------|
| Only ARP              | `arp`                                                 |
| Duplicate IPs         | `arp.duplicate-address-detected && arp.opcode == 2`   |
| Focus on one MAC      | `eth.addr == 08:00:27:53:0c:ba`                       |
| See what one MAC says | `arp && eth.src == 08:00:27:53:0c:ba`                 |

Indicators:

- One IP suddenly appears mapped to **two different MACs**.  
- A single host sends lots of unsolicited ARP replies.  
- A MAC that used to own `.5` now loudly claims to be `.4` as well.

---

### 4. Verifying on an Endpoint

On a Linux machine that might be under attack:

```bash
# Check the ARP cache for a suspicious MAC
arp -a | grep 08:00:27:53:0c:ba
```

If the same MAC shows up for multiple important IPs (like the gateway and another host), that’s a strong sign of spoofing in progress.

---

### 5. Hardening Options

- **Static ARP for critical nodes**  
  Pin the gateway’s IP → MAC mapping on key servers. This is extra admin work, but those entries cannot be spoofed.

- **Port security on switches**  
  Limit how many MAC addresses are allowed per switch port, and alert/block when a new one appears unexpectedly.

- **Dynamic ARP Inspection (DAI)**  
  On capable switches, use DAI so ARP replies are checked against a trusted database (e.g., DHCP snooping bindings) before being accepted.

