"""Unit tests for PhishGuard Engine (Module-1) — 16 Test Cases T01 to T16.

Directly validates every requirement R1 to R6 as specified in Section 4.1
of the Major Project Phase-1 Report and Slide 9 of the Project Presentation.
"""
import unittest
import time
from phishguard_engine import Model, ThreatIntel, BAND


class TestPhishGuardEngine(unittest.TestCase):
    def setUp(self):
        # Fresh model instance per test to prevent test state leakage (Bug B3 fix)
        self.model = Model()

    # T01: R1, R4 — Fake bank URL
    def test_T01_fake_bank_url(self):
        url = "http://secure-paypa1-login.account-verify.xyz/signin/update"
        res = self.model.run("url", url)
        self.assertEqual(res["label"], "Phishing")
        self.assertGreaterEqual(res["score"], 80)
        # Strong signal skips cascade
        self.assertEqual(res["pipeline"], "fast")

    # T02: R1 — Normal legitimate site
    def test_T02_normal_site(self):
        url = "https://www.wikipedia.org/wiki/Phishing"
        res = self.model.run("url", url)
        self.assertEqual(res["label"], "Looks safe")
        self.assertLess(res["score"], 10)

    # T03 (boundary): R1 — Long-URL rule at 90 vs 91 characters
    def test_T03_long_url_boundary(self):
        base = "https://www.example.com/search?q="
        url_90 = base + "a" * (90 - len(base))
        url_91 = base + "a" * (91 - len(base))
        self.assertEqual(len(url_90), 90)
        self.assertEqual(len(url_91), 91)

        sig_90 = self.model.analyze_url(url_90)
        sig_91 = self.model.analyze_url(url_91)
        self.assertNotIn("long_url", sig_90)
        self.assertIn("long_url", sig_91)

    # T04 (boundary): R4 — Uncertainty band escalation
    def test_T04_uncertainty_band(self):
        url = "http://account-verify.xyz/login"
        res = self.model.run("url", url)
        self.assertTrue(BAND[0] <= res["p_fast"] <= BAND[1])
        self.assertEqual(res["pipeline"], "escalated")
        self.assertIn("phish_feed_hit", res["signals"])

    # T05 (negative): R1 — Malformed URL
    def test_T05_malformed_url(self):
        url = "http://[::bad"
        res = self.model.run("url", url)
        self.assertIn("malformed_url", res["signals"])
        self.assertEqual(res["label"], "Phishing")

    # T06: R1 — Look-alike brand
    def test_T06_lookalike_brand(self):
        url = "https://paypa1.com/login"
        res = self.model.run("url", url)
        self.assertIn("brand_lookalike", res["signals"])

    # T07: R1 — Email with fused links
    def test_T07_email_links_fused(self):
        email_text = "URGENT invoice past due: verify immediately at http://secure-paypa1-login.account-verify.xyz"
        res = self.model.run("email", email_text)
        self.assertEqual(res["label"], "Phishing")
        self.assertIn("urgent", res["signals"])
        self.assertIn("brand_lookalike", res["signals"])

    # T08 (negative): R1 — Clean email
    def test_T08_clean_email(self):
        email_text = "Hey team, lunch notes from meeting at company.com are ready."
        res = self.model.run("email", email_text)
        self.assertEqual(res["label"], "Looks safe")

    # T09: R1 — Page with password form posting to external domain
    def test_T09_page_external_form(self):
        html = '<form action="http://evil.xyz/login"><input type="password" name="pwd"></form>'
        res = self.model.run("page", html)
        self.assertEqual(res["label"], "Phishing")
        self.assertIn("password_input", res["signals"])
        self.assertIn("external_form", res["signals"])

    # T10: R5 — Threat-intel cache
    def test_T10_threat_intel_cache(self):
        ti = ThreatIntel()
        ti.cache = {}  # isolated cache for clean test
        host = "account-verify.xyz"
        info1 = ti.lookup(host)
        info2 = ti.lookup(host)
        self.assertFalse(info1["cached"])
        self.assertTrue(info2["cached"])
        self.assertEqual(info2["registration"], "unknown")

    # T11: R2 — Explanation tiers and fidelity
    def test_T11_explanation_tiers(self):
        res = self.model.run("url", "http://secure-paypa1-login.account-verify.xyz/signin", full=True)
        t1 = self.model.tier1(res["signals"])
        t2 = self.model.tier2(res["signals"])
        t3 = self.model.tier3(res["signals"])

        fidelity = self.model.fidelity(t1, [x["signal"] for x in t2])
        self.assertGreaterEqual(fidelity, 0.50)
        self.assertTrue(t3.startswith("IF"))

    # T12: R3 — Novelty check
    def test_T12_novelty_check(self):
        # Known pattern
        known_sigs = ["ip_host", "no_https", "urgent"]
        novelty_known = self.model.novelty(known_sigs)
        self.assertLessEqual(novelty_known, 10)

        # Unseen / Zero-day pattern
        unseen_sigs = ["zero_day_token", "custom_exploit", "stealth_vector"]
        novelty_unseen = self.model.novelty(unseen_sigs)
        self.assertGreaterEqual(novelty_unseen, 50)

    # T13: R6 — Drift monitor
    def test_T13_drift_monitor(self):
        stable_scores = [10.0, 15.0, 12.0, 8.0, 14.0]
        drift_scores = [90.0, 85.0, 95.0, 92.0, 88.0]
        self.assertEqual(self.model.psi(stable_scores), "stable")
        self.assertEqual(self.model.psi(drift_scores), "drift")

    # T14: R3 — Feedback learns and promotes
    def test_T14_feedback_learns(self):
        case = {"signals": ["fake_bank", "urgent"]}
        initial_version = self.model.version
        promoted = self.model.give_feedback(case, label="Phishing")
        self.assertTrue(promoted)
        self.assertEqual(self.model.version, initial_version + 1)

    # T15 (negative): R6 — Promotion gate rejects false positive regression (Bug B4 fix)
    def test_T15_promotion_gate_rejects(self):
        # Stored feedback contains a delicate legitimate case at score boundary (score ~34)
        self.model.stored_feedback = [
            {"signals": ["fake_bank"], "ground_truth": 0}  # Legitimate entity with 'bank' word
        ]
        # Propose update that boosts 'fake_bank' weight by +2
        bad_case = {"signals": ["fake_bank"]}
        promoted = self.model.give_feedback(bad_case, label="Phishing")
        # Gate must reject to prevent false alarm regression
        self.assertFalse(promoted)
        self.assertEqual(self.model.version, 1)

    # T16: R4 — Scan latency budget
    def test_T16_scan_latency(self):
        times = []
        for _ in range(20):
            t0 = time.perf_counter()
            self.model.run("url", "https://www.example.com/page")
            times.append((time.perf_counter() - t0) * 1000)
        times.sort()
        p95 = times[int(0.95 * len(times))]
        self.assertLess(p95, 50.0)  # Budget: under 50 ms


if __name__ == "__main__":
    unittest.main()
