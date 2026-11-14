"""Deterministic, offline multi-vector feature extraction for URL, email, and HTML text."""
from __future__ import annotations
import math
import ipaddress
import re
from urllib.parse import urlparse
from collections import Counter

FEATURE_NAMES = [
    "type_url", "type_email", "type_html", "text_length", "dot_count",
    "hyphen_count", "digit_count", "at_count", "has_ip_host", "uses_https",
    "suspicious_word_count", "urgency_word_count", "credential_word_count",
    "url_count", "form_count", "password_field_count", "iframe_count",
    "external_link_count", "html_tag_count", "exclamation_count",
    # Advanced cybersecurity indicators
    "shannon_entropy", "has_punycode", "suspicious_tld", "subdomain_depth",
    "has_hex_or_octal_ip", "hidden_element_count", "cross_origin_form", "href_anchor_mismatch"
]

SUSPICIOUS_WORDS = (
    "verify", "secure", "account", "login", "update", "confirm", "bank",
    "wallet", "support", "alert", "payment", "prize", "invoice", "billing",
    "unauthorized", "suspended", "recover", "security"
)
URGENCY_WORDS = (
    "urgent", "immediately", "suspended", "expire", "today", "now",
    "limited", "final warning", "action required", "within 24 hours", "locked"
)
CREDENTIAL_WORDS = (
    "password", "credential", "sign in", "log in", "ssn", "one-time code",
    "otp", "pin", "passcode", "secret", "private key"
)
SUSPICIOUS_TLDS = (
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".buzz",
    ".club", ".support", ".click", ".link", ".stream", ".date", ".review",
    ".country", ".kim", ".cricket", ".science", ".party"
)

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
HREF_TAG_RE = re.compile(r'<a\b[^>]*href=[\'"]([^\'"]+)[\'"][^>]*>(.*?)</a>', re.I | re.S)


def _calc_entropy(text: str) -> float:
    """Calculate Shannon entropy of a character sequence."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _host_from_url(text: str) -> str:
    candidate = text.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.I):
        candidate = "http://" + candidate
    try:
        return (urlparse(candidate).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _is_obfuscated_ip(text: str) -> bool:
    """Check for hex (0x7f...), octal, or dword numeric IP patterns."""
    return bool(re.search(r"https?://(?:0x[0-9a-fA-F]+|[0-9]{8,12})\b", text))


def extract_features(input_type: str, text: str) -> dict[str, float]:
    """Return a fixed-order-compatible feature dictionary; never makes network requests."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Input text cannot be empty")

    itype = (input_type or "").strip().lower()
    if itype in ("url", "uri"):
        norm_type = "URL"
    elif itype in ("email", "mail", "email body", "email content", "text", "message", "html"):
        norm_type = "Email"
    else:
        raise ValueError("input_type must be URL or Email")

    lowered = text.lower()
    urls = URL_RE.findall(text)
    host = _host_from_url(text) if norm_type == "URL" else ""
    has_https = int(lowered.strip().startswith("https://")) if norm_type == "URL" else int("https://" in lowered)

    # Subdomain depth
    subdomains = host.split(".") if host else []
    subdomain_depth = max(0, len(subdomains) - 2) if len(subdomains) > 2 and not _is_ip(host) else 0

    # Suspicious TLD check
    suspicious_tld_flag = int(any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)) if host else 0
    if norm_type != "URL":
        for u in urls:
            u_host = _host_from_url(u)
            if any(u_host.endswith(tld) for tld in SUSPICIOUS_TLDS):
                suspicious_tld_flag = 1
                break

    # Anchor vs text mismatch (e.g. <a href="http://evil.com">https://paypal.com</a>)
    anchor_mismatches = 0
    for href, display in HREF_TAG_RE.findall(text):
        display_urls = URL_RE.findall(display)
        if display_urls:
            href_host = _host_from_url(href)
            display_host = _host_from_url(display_urls[0])
            if href_host and display_host and href_host != display_host:
                anchor_mismatches += 1

    entropy_target = host if norm_type == "URL" and host else text[:300]

    counts = {
        "type_url": int(norm_type == "URL"),
        "type_email": int(norm_type == "Email"),
        "type_html": 0,
        "text_length": len(text),
        "dot_count": text.count("."),
        "hyphen_count": text.count("-"),
        "digit_count": sum(ch.isdigit() for ch in text),
        "at_count": text.count("@"),
        "has_ip_host": int(_is_ip(host)),
        "uses_https": has_https,
        "suspicious_word_count": sum(lowered.count(word) for word in SUSPICIOUS_WORDS),
        "urgency_word_count": sum(lowered.count(word) for word in URGENCY_WORDS),
        "credential_word_count": sum(lowered.count(word) for word in CREDENTIAL_WORDS),
        "url_count": len(urls) + (1 if norm_type == "URL" else 0),
        "form_count": 0,
        "password_field_count": 0,
        "iframe_count": 0,
        "external_link_count": 0,
        "html_tag_count": 0,
        "exclamation_count": text.count("!"),
        # Advanced cybersecurity features
        "shannon_entropy": round(_calc_entropy(entropy_target), 4),
        "has_punycode": int("xn--" in lowered),
        "suspicious_tld": suspicious_tld_flag,
        "subdomain_depth": subdomain_depth,
        "has_hex_or_octal_ip": int(_is_obfuscated_ip(text)),
        "hidden_element_count": 0,
        "cross_origin_form": 0,
        "href_anchor_mismatch": anchor_mismatches,
    }
    return {name: float(counts[name]) for name in FEATURE_NAMES}


def heuristic_indicators(input_type: str, text: str) -> list[str]:
    """Human-readable rules, separate from the learned model output."""
    itype = (input_type or "").strip().lower()
    norm_type = "URL" if itype in ("url", "uri") else "Email"
    lower = text.lower()
    indicators: list[str] = []
    if norm_type == "URL":
        host = _host_from_url(text)
        if _is_ip(host):
            indicators.append("[CRITICAL] URL host is a raw IP address (common indicator of unverified hosting)")
        if _is_obfuscated_ip(text):
            indicators.append("[CRITICAL] Obfuscated hex or octal IP notation detected")
        if "xn--" in host:
            indicators.append("[CRITICAL] Punycode detected (IDN homograph attack spoofing look-alike letters)")
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            indicators.append("[WARNING] Host registered under a high-abuse top-level domain (TLD)")
        if host.count(".") >= 3:
            indicators.append("[WARNING] Excessive subdomain nesting detected (potential brand cloaking)")
        if len(text) > 75:
            indicators.append("[WARNING] Unusually long URL (> 75 chars)")
        if text.count("-") >= 3:
            indicators.append("[WARNING] Multiple hyphens in URL hostname or path")
        if "@" in text:
            indicators.append("[CRITICAL] '@' symbol present in URL (browser treats prefix as credentials, routing to suffix)")
        if not lower.strip().startswith("https://"):
            indicators.append("[WARNING] Insecure transmission: URL does not use HTTPS")

    if any(word in lower for word in URGENCY_WORDS):
        indicators.append("[WARNING] Psychological pressure: Urgency or countdown language detected")
    if any(word in lower for word in CREDENTIAL_WORDS):
        indicators.append("[CRITICAL] Credential harvesting: Password, OTP, or secret prompt detected")
    if any(word in lower for word in ("verify", "account", "payment", "bank", "wallet", "invoice", "suspended")):
        indicators.append("[WARNING] Impersonation cues: Financial or account verification terminology detected")

    # Mismatched links in email / text
    for href, display in HREF_TAG_RE.findall(text):
        display_urls = URL_RE.findall(display)
        if display_urls:
            href_host = _host_from_url(href)
            disp_host = _host_from_url(display_urls[0])
            if href_host and disp_host and href_host != disp_host:
                indicators.append(f"[CRITICAL] Deceptive link: Text says '{disp_host}' but points to '{href_host}'")
                break

    if not indicators:
        indicators.append("[INFO] No immediate heuristic flags triggered (heuristics do not guarantee safety)")
    return indicators
