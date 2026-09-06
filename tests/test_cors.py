#!/usr/bin/env python3
"""Tests for WEB9 — CORS Misconfiguration Scanner.

Hosts the built-in vulnerable/clean CORS simulators on loopback and runs the
real scan engine against them through urllib.
"""

import os
import sys
import threading
import unittest
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cors_scanner import (
    VulnCORHandler,
    CleanCORHandler,
    CORSScanner,
    CORSOriginReflector,
    CORSCredentialTester,
)


def _start(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class CORSDetectionTest(unittest.TestCase):
    def setUp(self):
        self.vuln = _start(VulnCORHandler)
        self.clean = _start(CleanCORHandler)
        self.addCleanup(self._close, self.vuln)
        self.addCleanup(self._close, self.clean)

    @staticmethod
    def _close(server):
        server.shutdown()
        server.server_close()

    def _vuln_url(self, extra="account"):
        return f"http://127.0.0.1:{self.vuln.server_port}/api/{extra}"

    def test_origin_reflected_on_vulnerable(self):
        r = CORSOriginReflector(self._vuln_url(), timeout=5)
        res = r.test_origin_reflection()
        self.assertTrue(any(x["reflected"] for x in res))
        reflected = [x for x in res if x["reflected"]]
        self.assertEqual(reflected[0]["acao"], "https://evil.com")

    def test_no_origin_reflection_on_clean(self):
        r = CORSOriginReflector(
            f"http://127.0.0.1:{self.clean.server_port}/api/account", timeout=5
        )
        res = r.test_origin_reflection()
        self.assertFalse(any(x["reflected"] for x in res))

    def test_credentialed_read_exploitable_on_vulnerable(self):
        t = CORSCredentialTester(self._vuln_url(), timeout=5)
        cred = t.test_credentialed_requests()
        self.assertTrue(any(c["exploitable"] for c in cred))

    def test_credentials_not_exploitable_on_clean(self):
        t = CORSCredentialTester(
            f"http://127.0.0.1:{self.clean.server_port}/api/account", timeout=5
        )
        cred = t.test_credentialed_requests()
        self.assertFalse(any(c["exploitable"] for c in cred))

    def test_preflight_reflection_on_vulnerable(self):
        r = CORSOriginReflector(self._vuln_url(), timeout=5)
        pre = r.test_preflight_reflection()
        self.assertTrue(any(p["preflight_accepted"] for p in pre))

    def test_full_scan_counts_on_vulnerable(self):
        scanner = CORSScanner(self._vuln_url(), timeout=5)
        scanner.scan()
        self.assertGreater(scanner.count_vulnerabilities(), 0)

    def test_full_scan_zero_on_clean(self):
        scanner = CORSScanner(
            f"http://127.0.0.1:{self.clean.server_port}/api/account", timeout=5
        )
        scanner.scan()
        self.assertEqual(scanner.count_vulnerabilities(), 0)


class CORDDemoTest(unittest.TestCase):
    def test_demo_vulnerable_returns_0(self):
        import cors_scanner
        self.assertEqual(cors_scanner.run_demo(clean=False), 0)

    def test_demo_clean_returns_0(self):
        import cors_scanner
        self.assertEqual(cors_scanner.run_demo(clean=True), 0)


if __name__ == "__main__":
    unittest.main()