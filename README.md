# WEB9 — CORS Misconfiguration Scanner

CORS header analysis, origin reflection testing, preflight abuse, and credential theft PoC.

## Overview

This project identifies and demonstrates CORS (Cross-Origin Resource Sharing) misconfigurations:
- **Header analysis** — Inspect CORS headers for known vulnerability patterns
- **Origin reflection** — Test if arbitrary origins are reflected
- **Credential testing** — Verify if credentialed cross-origin requests are allowed
- **Preflight abuse** — Test method and header override via OPTIONS
- **PoC generation** — Create working exploit HTML and receiver server

## Features

- CORS header analysis with vulnerability classification
- Origin reflection testing (evil.com, null, subdomains)
- Credentialed request testing (cookies, auth tokens)
- Preflight (OPTIONS) method and header override testing
- Working cookie-theft PoC HTML generator
- Built-in HTTP receiver server for PoC demonstrations
- JSON and formatted report output

## Requirements

- Python 3.8+
- No external dependencies (standard library only)

## Usage

```bash
# Full CORS scan
python3 cors_scanner.py --url http://api.example.com/data --report

# Generate PoC HTML file
python3 cors_scanner.py --url http://api.example.com/data --poc

# Start receiver server for PoC testing
python3 cors_scanner.py --url http://api.example.com/data --poc --server --port 8899

# JSON output
python3 cors_scanner.py --url http://api.example.com/data --json
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
