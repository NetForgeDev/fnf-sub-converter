# F&F Xray Subscription Converter (Cloudflare Worker)

A lightweight, single-file **Cloudflare Worker** with a built-in web admin panel that applies **Patterniha's F&F (Fragment, Cipher Suites & Fingerprint) method** (`cs`, `fm`, `fp`) to your existing subscriptions or personal configs to help bypass DPI and firewall filtering.

> **Supported Protocols:** `VLESS`, `Trojan`, and `VMess` (strictly filtered to **TLS** configs with `WS`, `HTTPUpgrade`, `XHTTP`, `gRPC`, or `TCP` transports).

---

## ✨ Features

- **Applies Patterniha's F&F Method:** Automatically injects `cs` (TLS Cipher Suites), `fm` (Final Mask / Fragment JSON), and `fp` (TLS Fingerprint) into clean Xray share links.
- **Universal Input Auto-Detection:** Accepts **Sing-box JSON**, **Xray JSON**, and **V2Ray/Xray URI subscriptions** (both raw text and Base64 / URL-safe Base64), or even raw pasted configs.
- **Strict TLS & Transport Filtering:** Keeps only `security=tls` configs matching your selected transports (`WS`, `HTTPUpgrade`, `XHTTP`, `gRPC`, and `TCP` — all enabled by default), filtering out incompatible non-TLS, Reality, and UDP-based nodes.
- **Clean IP Pool (IPv4 & IPv6):** Save custom lists containing mixed IPv4 and IPv6 addresses and choose per subscription:
  - **IPv4 only** (assigns a random IPv4 per server)
  - **IPv6 only** (assigns a random IPv6 per server)
  - **IPv4 + IPv6** (generates **2 configs per server**: one with random IPv4 and one with random IPv6)
  - **IPv4/IPv6** (picks 1 random IP from the combined list per server)
  - Or keep the **Original Server IP**
- **Preset Management:** Store and manage reusable presets for Cipher Suites (`cs`), Final Mask (`fm` with built-in v1 & v2 templates), and Clean IP lists.
- **Secure Admin Panel:** Protected with password login and HMAC-signed session cookies. Both the admin panel URL path and password can be changed directly inside the panel.
- **Live Preview & Flexible Output:** Preview converted configs in the browser before using them, and output either plain text or Base64 (`?raw=1` / `?b64=1` supported).

---

## 🚀 Quick Deployment on Cloudflare Workers (Dashboard)

You don't need any build tools or CLI—just copy and paste:

1. **Create a KV Namespace:**
   - Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/).
   - Go to **Storage & Databases → KV** and click **Create a namespace** (e.g., name it `SUB_KV_STORE`).

2. **Create the Worker:**
   - Go to **Workers & Pages → Create → Create Worker**.
   - Give it a name and click **Deploy**.
   - Click **Edit code**, delete the default code, paste the full contents of [`worker.js`](./worker.js), and click **Deploy**.

3. **Bind the KV Namespace:**
   - In your Worker's page, go to **Settings → Bindings**.
   - Click **Add → KV Namespace**.
   - Set **Variable name** to **`SUB_KV`** *(exact match required)*.
   - Select the KV namespace you created in Step 1 and save.

4. **Access the Admin Panel:**
   - Open `https://<your-worker>.workers.dev/panel`
   - Default password: **`admin123`**
   - Go to **Panel Settings** immediately after logging in to change your admin path (e.g., `/my-secret-panel`) and password.

---

## 🛠️ Usage

1. Open the **Clean IPs**, **Cipher Suites (cs)**, and **Final Mask (fm)** tabs if you want to add your custom presets (default `cs` and Fragment `v1`/`v2` presets are already preloaded).
2. In the **Subscriptions** tab, paste your input subscription URL(s) (or raw configs), choose your desired `fp`, `cs`, `fm`, Clean IP mode, allowed transports, and IP version checkboxes, then save.
3. Copy the generated `/sub/...` link and import it into a compatible client.
   - Tip: Append `?raw=1` for plain text output or `?b64=1` for Base64 output.

---

## 📱 Recommended Clients

To use the generated subscriptions with full `cs` and `fm` support, use one of the following clients:

- **Android:**
  - [PattNG](https://github.com/patterniha/PattNG)
  - [Throne for Android](https://github.com/throneproj/ThroneForAndroid)
- **Windows:**
  - [PattN](https://github.com/patterniha/PattN)
  - [Throne](https://github.com/throneproj/Throne)

---

## ⚠️ Disclaimer

- This tool is intended for educational and personal network research purposes.
- Non-TLS, Reality, and UDP-based configs are intentionally excluded from the output because F&F (`cs` and `fm`) parameters require TLS over TCP-based transports.

<sub>Developed with AI assistance.</sub>
