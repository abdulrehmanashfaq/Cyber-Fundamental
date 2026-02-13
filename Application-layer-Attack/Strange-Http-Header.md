## Strange HTTP Headers and What They Can Tell You

When attackers don’t want to stand out via volume, they get creative with HTTP headers. This can help them reach internal services, poison logic, or smuggle extra requests.

---

### 1. Abusing the Host Header

The `Host` header decides which virtual host the request is routed to. If an application or reverse proxy trusts it too much, small changes can have big effects.

#### 1.1 Common Abuse Patterns

- **Pretending to be local**  
  Sending `Host: 127.0.0.1` or `Host: localhost` so the request is treated as if it came from the server itself, possibly exposing `/server-status` or internal admin panels.

- **Virtual host discovery**  
  Cycling through `admin.example.com`, `dev.example.com`, `staging.example.com`, etc. to find internal sites living behind the same IP.

- **Password reset poisoning**  
  Setting `Host` to an attacker‑controlled domain so password‑reset links or verification emails point to the wrong place.

#### 1.2 Simple Host‑Based Hunting

| Tool      | Example idea                                                      |
|-----------|-------------------------------------------------------------------|
| Wireshark | `http.request && !(http.host == "expected.domain.com")`          |
| Tshark    | `tshark -r traffic.pcap -Y "http.request" -T fields -e http.host`|

Anything consistently outside your approved host list deserves attention.

---

### 2. Request Smuggling and CRLF Tricks

Request smuggling often comes down to convincing a front‑end proxy and a back‑end server to parse the same bytes differently. One way is to inject raw CR (`%0d`) and LF (`%0a`) characters into the request.

#### 2.1 Example: Apache Rewrite + Proxy (CVE‑2023‑25690 Style)

If a reverse proxy uses `mod_proxy` and `mod_rewrite` like:

```apache
RewriteRule "^/categories/(.*)" "http://192.168.10.100:8080/categories.php?id=$1" [P]
```

and the attacker controls `$1`, they can craft something like:

```http
GET /categories/1%20HTTP/1.1%0d%0aHost:localhost%0d%0a%0d%0aGET%20/admin HTTP/1.1
```

Now the front‑end and back‑end may disagree on where the first request ends and the second begins.

#### 2.2 What It Looks Like in Logs/PCAPs

- A `400 Bad Request` from the proxy or backend when parsing gets confused.  
- Immediately afterwards, a `200 OK` to a sensitive internal path from the same client.

Correlating those back‑to‑back events is a strong hint of smuggling activity.

---

### 3. Odd HTTP Methods

Most day‑to‑day web traffic is `GET` and `POST`. Other verbs can be legitimate but are also useful probes.

- `OPTIONS` – Discover which operations the server is willing to perform.  
- `PUT` / `DELETE` – Upload or remove files; often abused to plant web shells.  
- `TRACE` – Can echo back request headers and help attackers bypass `HttpOnly` cookies in some misconfigurations.

Filter to highlight this:

```text
http.request.method != "GET" && http.request.method != "POST"
```

Then review whether the target endpoints should ever accept those methods.

---

### 4. User-Agent as a Weak but Useful Signal

The `User-Agent` header is easy to fake, but still offers hints:

- Clear tool fingerprints like `sqlmap`, `Nikto`, or certain scanners.  
- Completely missing or empty user agents from hastily written scripts.  
- Very outdated browser strings tied to exploit frameworks.

This should never be your only detection, but it’s a good pivot field.

---

### 5. Hardening Checklist

- **Enforce strict Host rules**  
  Reject or redirect any request whose `Host` is not on an allowlist.

- **Limit allowed methods**  
  Use web‑server directives (`LimitExcept`, `AllowMethods`, etc.) to only permit verbs your app actually uses.

- **Normalize and sanitize input**  
  Have your WAF or reverse proxy strip dangerous control characters (CR/LF) from headers and URLs when possible.

- **Stay patched**  
  Keep proxies (like Apache, Nginx, HAProxy) updated so known request‑smuggling bugs such as CVE‑2023‑25690 are closed.


