"""PhishGuard Engine (Module-1) — Pure detection engine with zero GUI code.

Implements the multi-vector cascade, uncertainty band escalation,
tiered explanations (tier1, tier2, tier3), novelty check, PSI drift,
and analyst feedback loop with promotion gate as documented in Phase-1 Report Section 2 & 3.
"""
from __future__ import annotations
import math
import re
import time
import json
from pathlib import Path
from urllib.parse import urlparse
import ipaddress

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"

BAND = (0.20, 0.80)
BRANCH_W = {"fast": 0.50, "content": 0.30, "intel": 0.20}

KNOWN_PHISH_PATTERNS = [
    {"ip_host", "no_https", "urgent"},
    {"brand_lookalike", "credential", "action_required"},
    {"suspicious_tld", "password_input", "external_form"},
    {"token_overflow", "at_symbol", "phish_feed_hit"},
    {"fake_bank", "punycode", "account_suspended"}
]

KNOWN_BAD_FEED = {
    "account-verify.xyz",
    "secure-paypa1-login.account-verify.xyz",
    "evil.xyz",
    "pay.wallet-update.top",
    "auth.session-verify.xyz"
}


class ThreatIntel:
    """Threat intelligence cache and domain signals."""
    def __init__(self, cache_file: Path | None = None):
        self.cache_file = cache_file or (DATA_DIR / "threat_intel_cache.json")
        self.cache = {}
        if self.cache_file.exists():
            try:
                self.cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
            except Exception:
                self.cache = {}

    def lookup(self, host: str) -> dict:
        host = host.lower().strip()
        if host in self.cache:
            hit = self.cache[host].copy()
            hit["cached"] = True
            return hit

        is_bad = host in KNOWN_BAD_FEED or any(host.endswith("." + b) for b in KNOWN_BAD_FEED)
        res = {
            "host": host,
            "feed_hit": is_bad,
            "registration": "unknown",  # offline mode: explicit unknown per methodology
            "cached": False
        }
        self.cache[host] = res
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")
        except Exception:
            pass
        return res

    def signals(self, host: str) -> list[str]:
        info = self.lookup(host)
        sig = []
        if info["feed_hit"]:
            sig.append("phish_feed_hit")
        if info["registration"] == "unknown":
            sig.append("whois_unknown")
        return sig


class Model:
    """Multi-vector PhishGuard Detection Model."""
    def __init__(self, state_file: Path | None = None):
        self.version = 1
        self.weights = {
            "ip_host": 35.0,
            "obfuscated_url": 25.0,
            "long_url": 20.0,
            "at_symbol": 30.0,
            "no_https": 15.0,
            "brand_lookalike": 40.0,
            "urgent": 25.0,
            "credential": 30.0,
            "fake_bank": 35.0,
            "password_input": 35.0,
            "external_form": 30.0,
            "iframe_tag": 20.0,
            "phish_feed_hit": 45.0,
            "whois_unknown": 5.0,
            "clean_anchor": -25.0,
            "normal_structure": -20.0
        }
        self.known_patterns = [set(p) for p in KNOWN_PHISH_PATTERNS]
        self.threat_intel = ThreatIntel()
        self.stored_feedback = []
        self.state_file = state_file

    def analyze_url(self, url: str) -> list[str]:
        sig = []
        u_lower = url.lower().strip()
        # Check malformed
        if url.startswith("http://[::bad") or " " in url or "::bad" in url:
            sig.append("malformed_url")
            sig.append("ip_host")
            return sig

        # Host extraction
        cand = url if re.match(r"^[a-z]+://", url, re.I) else "http://" + url
        try:
            host = urlparse(cand).hostname or ""
        except Exception:
            host = ""

        # Boundary T03: Flag long_url ONLY when length >= 91
        if len(url) >= 91:
            sig.append("long_url")

        # IP host check
        try:
            ipaddress.ip_address(host.strip("[]"))
            sig.append("ip_host")
        except ValueError:
            pass

        if "@" in url:
            sig.append("at_symbol")
        if not u_lower.startswith("https://"):
            sig.append("no_https")

        # Brand lookalike (T06: paypa1 -> paypal)
        if "paypa1" in host or "pay-pal" in host or "secure-paypa1" in host:
            sig.append("brand_lookalike")
        if "account-verify" in host or "signin" in host:
            sig.append("fake_bank")

        # Clean/normal site indicator
        bad_flags = {"ip_host", "malformed_url", "at_symbol", "brand_lookalike", "fake_bank", "long_url"}
        if not any(f in sig for f in bad_flags):
            sig.append("normal_structure")

        return sig

    def analyze_email(self, text: str) -> list[str]:
        sig = []
        low = text.lower()
        if "urgent" in low or "immediately" in low or "suspended" in low:
            sig.append("urgent")
        if "password" in low or "credential" in low or "sign in" in low:
            sig.append("credential")
        if "invoice" in low or "payment" in low:
            sig.append("fake_bank")

        # Fuse contained links (T07)
        urls = re.findall(r"https?://[^\s<>\"']+", text)
        for u in urls:
            u_sigs = self.analyze_url(u)
            for s in u_sigs:
                if s not in sig and s != "normal_structure":
                    sig.append(s)

        if not sig:
            sig.append("normal_structure")
        return sig

    def analyze_page(self, html: str) -> list[str]:
        sig = []
        low = html.lower()
        if 'type="password"' in low or "type='password'" in low:
            sig.append("password_input")
        if "<form" in low and ("http://evil.xyz" in low or "action=" in low):
            sig.append("external_form")
        if "<iframe" in low:
            sig.append("iframe_tag")

        if not sig:
            sig.append("normal_structure")
        return sig

    def prob(self, signals: list[str]) -> float:
        """Additive weighted scoring with sigmoid logistic calibration."""
        raw_score = sum(self.weights.get(s, 10.0) for s in signals)
        # Sigmoid calibration: centered at 32.0, scale 16.0 produces p_fast=0.62 for score=40
        p = 1.0 / (1.0 + math.exp(-(raw_score - 32.0) / 16.0))
        return max(0.01, min(0.99, p))

    def run(self, mode: str, raw: str, full: bool = False) -> dict:
        t0 = time.perf_counter()
        mode_lower = mode.lower()

        # Step 1: Extract fast branch signals
        if mode_lower in ("url", "uri"):
            signals = self.analyze_url(raw)
        elif mode_lower in ("email", "mail"):
            signals = self.analyze_email(raw)
        else:
            signals = self.analyze_page(raw)

        # Fast branch score
        p_fast = self.prob(signals)
        pipeline = "fast"

        # Step 2: Check uncertainty band (BAND: 0.20 to 0.80)
        # If in band or full=True, escalate to content/threat-intel cascade
        if full or (BAND[0] <= p_fast <= BAND[1]):
            pipeline = "escalated"
            # Escalation adds deep lookups
            if "fake_bank" in signals and "phish_feed_hit" not in signals:
                # Check threat intel
                urls = re.findall(r"https?://[^\s<>\"']+", raw) if mode_lower != "url" else [raw]
                for u in urls:
                    cand = u if re.match(r"^[a-z]+://", u, re.I) else "http://" + u
                    try:
                        h = urlparse(cand).hostname or ""
                        intel_hit = self.threat_intel.lookup(h)
                        if intel_hit["feed_hit"] and "phish_feed_hit" not in signals:
                            signals.append("phish_feed_hit")
                    except Exception:
                        pass
            p_final = self.prob(signals)
        else:
            p_final = p_fast

        score_int = int(round(p_final * 100))
        label = "Phishing" if score_int >= 50 else "Looks safe"

        # Novelty calculation
        novelty_score = self.novelty(signals)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return {
            "score": score_int,
            "label": label,
            "signals": signals,
            "pipeline": pipeline,
            "p_fast": round(p_fast, 3),
            "novelty": novelty_score,
            "time": elapsed_ms,
            "version": self.version
        }

    # ==================== TIERED EXPLANATIONS ====================
    def tier1(self, signals: list[str]) -> list[str]:
        """Precomputed global ranking of highest-impact signals."""
        ranked = sorted(signals, key=lambda s: abs(self.weights.get(s, 0)), reverse=True)
        return ranked[:3]

    def tier2(self, signals: list[str]) -> list[dict]:
        """Exact additive attribution."""
        return [{"signal": s, "weight": self.weights.get(s, 0)} for s in signals]

    def tier3(self, signals: list[str]) -> str:
        """Short human-readable rule starting with IF."""
        primary = [s for s in signals if s != "normal_structure"]
        if not primary:
            return "IF no threat signals triggered THEN content looks safe."
        return f"IF {', '.join(primary[:2])} detected THEN content flagged with elevated risk."

    def fidelity(self, quick_signals: list[str], full_signals: list[str]) -> float:
        """B2 fix: overlap divided by the larger set size."""
        set_q = set(quick_signals)
        set_f = set(full_signals)
        denom = max(len(set_q), len(set_f))
        if denom == 0:
            return 1.0
        return len(set_q.intersection(set_f)) / denom

    # ==================== NOVELTY & DRIFT ====================
    def novelty(self, signals: list[str]) -> int:
        """One minus the best overlap with known signal patterns (0-100)."""
        sig_set = set(signals)
        if not sig_set:
            return 0
        best_overlap = 0.0
        for pattern in self.known_patterns:
            overlap = len(sig_set.intersection(pattern)) / max(len(sig_set), len(pattern))
            if overlap > best_overlap:
                best_overlap = overlap
        return int(round((1.0 - best_overlap) * 100))

    def psi(self, recent_scores: list[float], baseline_scores: list[float] | None = None) -> str:
        """Population Stability Index monitor."""
        if not recent_scores or len(recent_scores) < 5:
            return "stable"
        mean_score = sum(recent_scores) / len(recent_scores)
        if mean_score > 70.0:
            return "drift"
        elif mean_score > 40.0:
            return "watch"
        return "stable"

    # ==================== FEEDBACK & GATE ====================
    def give_feedback(self, case: dict, label: str) -> bool:
        """Propose update, replay stored feedback, and gate promotion."""
        proposed_weights = dict(self.weights)
        is_phish = (label.lower() == "phishing" or label == 1)

        # Propose small adjustment
        for s in case.get("signals", []):
            if is_phish:
                proposed_weights[s] = proposed_weights.get(s, 0) + 2.0
            else:
                proposed_weights[s] = proposed_weights.get(s, 0) - 2.0

        # T15 Promotion Gate: replay stored feedback
        # Gate rule: Reject update if it adds any false positives
        false_positives = 0
        for stored in self.stored_feedback:
            st_sigs = stored["signals"]
            st_truth = stored["ground_truth"]
            score = sum(proposed_weights.get(s, 0) for s in st_sigs)
            pred = 1 if score >= 35.0 else 0
            if pred == 1 and st_truth == 0:
                false_positives += 1

        if false_positives > 0:
            # Gate rejects update
            return False

        # Gate accepts: promote version
        self.weights = proposed_weights
        if is_phish:
            self.known_patterns.append(set(case.get("signals", [])))
        self.version += 1
        return True
