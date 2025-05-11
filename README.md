# Wpen - Web Pentest Toolkit 🔍

Wpen is a powerful, beginner-friendly **web pentesting toolkit** packed with over 30+ tools for reconnaissance, scanning, exploitation, and analysis.  
Perfect for bug bounty hunters, CTF players, security researchers, and developers learning web security.

Author: Cr3zy  
GitHub: https://github.com/Cr3zy-dev  
License: GPL v3  
Version: 1.0.0

---

> **⚠️ Disclaimer:**  
> WPen is developed strictly for educational and ethical purposes only.  
> The developers and contributors are **NOT** responsible for any misuse of this toolkit.  
> You are solely responsible for your actions.  
> Do **NOT** use WPen to target or harm any system or network without explicit permission from the owner.  
> Unauthorized use of this tool may be illegal and can result in criminal charges.  
> Always use WPen in accordance with local laws and regulations.
>
> WPen © 2025 Cr3zy ([GitHub Profile](https://github.com/Cr3zy-dev))  
> Licensed under the [GNU General Public License v3.0](LICENSE).

---

## 🚀 Features

✅ 30+ built-in tools (... and more coming soon!)
✅ No API keys needed  
✅ Supports custom wordlists  
✅ Designed for automation and recon  
✅ CLI-based, simple, fast, and effective  
✅ Built-in dependency check and help system

---

## 🛠 Installation

### On Windows

1. **Clone or download** this repository:
   ```bash
   git clone https://github.com/Cr3zy-dev/wpen.git
   ```
2. **Navigate into the folder**:
   ```bash
   cd wpen
   ```
3. **Install required Python modules**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run WPen**:
   ```bash
   python wpen.py
   ```

### On Linux

1. **Make sure Python and pip are installed**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   ```
2. **Clone the repository**:
   ```bash
   git clone https://github.com/Cr3zy-dev/wpen.git
   ```
3. **Navigate into the folder**:
   ```bash
   cd wpen
   ```
4. **Install dependencies**:
   ```bash
   pip3 install -r requirements.txt
   ```
5. **Run WPen**:
   ```bash
   python3 wpen.py
   ```
---

## ⚠️ Important for Kali Linux users

If you encounter an error like "externally-managed-environment" when installing modules:
- **Option 1 (quick and easy):** Install with --break-system-packages flag:
   ```bash
   pip3 install -r requirements.txt --break-system-packages
   ```
- **Option 2 (recommended):** Use a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

---

## 🧰 Tools Included

| #  | Tool Name                     | Description                                                |
|----|------------------------------|------------------------------------------------------------|
| 01 | URL Crawler                  | Discovers links, scripts, forms on target site             |
| 02 | Subdomain Finder             | Bruteforces subdomains                                     |
| 03 | CMS Detector                 | Detects WordPress, Joomla, Drupal, etc.                    |
| 04 | Headers Analyzer             | Prints HTTP headers and cookies                            |
| 05 | HTTP Request Sender          | Sends customizable HTTP requests                           |
| 06 | Form Scanner                 | Extracts forms and fields                                  |
| 07 | SQL Injection Tester         | Tests for SQLi via forms                                   |
| 08 | XSS Tester                   | Reflected XSS payload tester                               |
| 09 | Open Directory Finder        | Bruteforce common directories                              |
| 10 | WordPress Scanner            | Detects version, plugins, themes                           |
| 11 | Port Scanner                 | Scans open TCP ports                                       |
| 12 | LFI/RFI Scanner              | Local/Remote File Inclusion detection                      |
| 13 | CORS Checker                 | Detects misconfigured CORS policies                        |
| 14 | Open Redirect Tester         | Tests for redirect-based vulnerabilities                   |
| 15 | SSRF Tester                  | Detects server-side request forgery                        |
| 16 | CSP Analyzer                 | Analyzes Content-Security-Policy headers                   |
| 17 | JS Endpoint Scanner          | Extracts endpoints from JavaScript files                   |
| 18 | Exposed Files Finder         | Checks for .git, .env, backups, etc.                       |
| 19 | 403 Bypasser                 | Tries bypass methods (encoding, verb tampering)            |
| 20 | JSONP Callback Finder        | Tests for insecure JSONP endpoints                         |
| 21 | Wayback URL Extractor        | Dumps old URLs from archive.org                            |
| 22 | Parameter Pollution Tester   | Tests for duplicate parameter injection                    |
| 23 | Sitemap & robots.txt Parser  | Extracts hidden and disallowed paths                       |
| 24 | JS Secrets Finder            | Finds secrets in JavaScript: keys, tokens, emails, etc.    |
| 25 | Host Header Injection Tester | Tests for cache poison, redirect via Host spoofing         |
| 26 | Redirect Chain Tracer        | Logs all redirects (HTTP + JS + Meta)                      |
| 27 | JWT Token Analyzer           | Extracts and decodes JWTs from headers/cookies             |
| 28 | CVE Version Scanner          | Matches versions to known CVEs (offline, local file)       |
| 29 | WAF Detector                 | Tests if a firewall is blocking malicious payloads         |
| 30 | HTTP Timing Analyzer         | Measures response variance (detect filters/throttling)     |
| 98 | Tool Info Center             | Shows what each tool does for beginners                    |

---

## 📸 Screenshots

> _(Add your terminal screenshots or GIFs here – e.g., how `01`, `05`, or `27` look in action.)_

---

## 📚 Requirements

- Python 3.8+
- `colorama`
- `requests`
- `beautifulsoup4`
- `PyJWT`

You can install all dependencies easily using:
pip install -r requirements.txt

---

## 📄 License

Wpen is released under the [GPL v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html)

---
