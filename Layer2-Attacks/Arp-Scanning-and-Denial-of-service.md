## ARP Scans and Turning Them into a Subnet DoS

This note explains how attackers use ARP first to **map** a LAN and then to **knock it offline**, plus what to look for in captures.

---

### 1. Phase One: “Who’s Alive?” – ARP Scanning

Normal ARP chatter is fairly random: hosts ask for addresses as they need them.  
During a scan, the pattern changes:

- One MAC walks the entire subnet (`.1`, `.2`, `.3`, …).  
- It asks for IPs that don’t correspond to any real host.  
- The source MAC is constant and often belongs to a machine running tools like Nmap or Netdiscover.

In other words, you see a **single MAC asking about everyone** in a very short time window.

---

### 2. Phase Two: From Recon to Blackout

Once the attacker knows which IPs are in use, they can poison the ARP tables of:

- The **gateway** – convincing the router that every IP maps to the attacker’s MAC.  
- The **clients** – convincing all workstations that the attacker is the default gateway.

If the attacker stops forwarding traffic at that point:

- Client → attacker (instead of gateway).  
- Internet → attacker (instead of the real host).  
- Result: the whole subnet appears “down” from the users’ perspective.

---

### 3. Hunting ARP Scans and DoS in PCAPs

#### 3.1 Finding the Scanner

Wireshark display filter:

```text
arp.opcode == 1 && eth.src == [Source_MAC]
```

Then:

- Sort by time and look for **bursts** of ARP Requests to sequential IPs.  
- Ten or more requests in a single second to neighboring addresses is already suspicious.

#### 3.2 Catching the Subnet‑Wide Poison

To catch the “everything now lives at my MAC” move:

```text
arp.duplicate-address-detected && arp.opcode == 2
```

If many different IPs are suddenly “duplicate” but all point to the same MAC, you’re seeing a broad poison attempt.

#### 3.3 Quick CLI View with TShark

```bash
# See which IPs a given MAC is scanning for
tshark -r ARP_Scan.pcapng \
  -Y "eth.src == 08:00:27:53:0c:ba" \
  -T fields -e arp.dst.proto_ipv4
```

---

### 4. Practical Response Steps

- **1) Trace the cable**  
  Use your switch’s MAC table to figure out where the attacker’s MAC is plugged in:

  ```text
  show mac address-table address [Attacker_MAC]
  ```

- **2) Isolate the port**  
  Shut down the offending interface so it can’t continue poisoning:

  ```text
  interface [Port_ID]
    shutdown
  ```

- **3) Contain wireless sources**  
  If the hostile device is on Wi‑Fi (evil twin AP, rogue client), use deauth or your WLAN controller’s containment features to disconnect it.

