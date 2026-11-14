"""Local, offline threat intelligence and signature repository for PhishGuard."""
from __future__ import annotations
import json
from pathlib import Path
from urllib.parse import urlparse
import re

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"

KNOWN_BAD_DOMAINS = {
    "secure-paypa1-login.account-verify.xyz",
    "account-verify.xyz",
    "evil.xyz",
    "pay.wallet-update.top",
    "auth.session-verify.xyz",
    "billing-check.xyz",
    "crypto-login.buzz",
    "external-catcher.xyz",
    "harvester.top",
    "steal-credentials.xyz",
}

KNOWN_GOOD_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "github.com",
    "wikipedia.org", "python.org", "reva.edu.in", "acm.org",
    "ieee.org", "amazon.com", "paypal.com", "chase.com"
}


class ThreatIntel:
    """Offline domain reputation and cached threat intelligence."""

    def __init__(self, cache_file: Path | None = None):
        self.cache_file = cache_file or (DATA_DIR / "threat_intel_cache.json")
        self.cache: dict[str, dict] = self._load_cache()

    def _load_cache(self) -> dict[str, dict]:
        if self.cache_file.exists():
            try:
                return json.loads(self.cache_file.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")
        except Exception:
            pass

    def extract_host(self, url: str) -> str:
        candidate = url.strip()
        if not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.I):
            candidate = "http://" + candidate
        try:
            return (urlparse(candidate).hostname or "").lower()
        except ValueError:
            return ""

    def lookup(self, host_or_url: str) -> dict:
        """Query offline threat intelligence cache and feed signatures."""
        host = self.extract_host(host_or_url) if ("/" in host_or_url or "." in host_or_url) else host_or_url.lower()
        if not host:
            return {
                "host": host,
                "reputation": "neutral",
                "feed_hit": False,
                "domain_age": "unknown",
                "whois_status": "offline_explicit_unknown",
                "risk_adjustment": 0.0,
                "source": "empty_input"
            }

        # Check local in-memory/disk cache first
        if host in self.cache:
            hit = self.cache[host].copy()
            hit["cached"] = True
            return hit

        # Check curated local threat feeds
        reputation = "neutral"
        risk_adj = 0.0
        feed_hit = False
        reasons = []

        if host in KNOWN_BAD_DOMAINS or any(host.endswith("." + bad) for bad in KNOWN_BAD_DOMAINS):
            reputation = "malicious"
            risk_adj = 0.45
            feed_hit = True
            reasons.append("Matched known phishing campaign domain in local feed")

        elif host in KNOWN_GOOD_DOMAINS or any(host.endswith("." + good) for good in KNOWN_GOOD_DOMAINS):
            reputation = "trusted"
            risk_adj = -0.40
            reasons.append("Verified high-reputation domain in local allowlist")

        info = {
            "host": host,
            "reputation": reputation,
            "feed_hit": feed_hit,
            "domain_age": "unknown (offline mode: network WHOIS disabled by design)",
            "whois_status": "offline_explicit_unknown",
            "risk_adjustment": risk_adj,
            "reasons": reasons,
            "source": "local_threat_feed",
            "cached": False
        }

        self.cache[host] = info
        self._save_cache()
        return info


_default_intel = ThreatIntel()


def check_threat_intel(host_or_url: str) -> dict:
    return _default_intel.lookup(host_or_url)

