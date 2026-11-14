import pytest
from phishing.features import extract_features, heuristic_indicators, FEATURE_NAMES
from phishing.few_shot import few_shot_predict
from phishing.adversarial import synthetic_variants
from phishing.threat_intel import ThreatIntel
from phishing.mlops import calculate_psi, MLOpsManager


def test_feature_extraction_fixed_schema():
    features = extract_features("URL", "https://www.example.com/about")
    assert list(features.keys()) == FEATURE_NAMES
    assert len(FEATURE_NAMES) == 28
    assert features["type_url"] == 1
    assert features["uses_https"] == 1
    assert "shannon_entropy" in features
    assert "suspicious_tld" in features


def test_invalid_type_and_empty_input_rejected():
    with pytest.raises(ValueError):
        extract_features("PDF", "some text")
    with pytest.raises(ValueError):
        extract_features("Email", "   ")


def test_advanced_cybersecurity_features():
    # Test punycode detection
    puny_f = extract_features("URL", "http://xn--pypal-4ve.com/login")
    assert puny_f["has_punycode"] == 1.0

    # Test suspicious TLD detection
    tld_f = extract_features("URL", "http://login.account-update.xyz/signin")
    assert tld_f["suspicious_tld"] == 1.0

    # Test anchor mismatch
    html_mismatch = '<a href="http://evil.com">https://paypal.com</a>'
    mismatch_f = extract_features("HTML", html_mismatch)
    assert mismatch_f["href_anchor_mismatch"] >= 1.0


def test_email_indicators_are_heuristics():
    indicators = heuristic_indicators("Email", 'URGENT: Verify your password immediately at http://login.bank.xyz')
    assert any("Urgency" in item or "psychological" in item.lower() for item in indicators)
    assert any("Credential" in item or "harvesting" in item.lower() for item in indicators)


def test_few_shot_returns_known_class():
    result = few_shot_predict("Email", "Urgent verify your password now", [
        ("Hello, here are the lecture notes", 0),
        ("URGENT verify your password immediately", 1),
    ])
    assert result["class_id"] in (0, 1)
    assert "note" in result
    assert 0 in result["distances"]
    assert 1 in result["distances"]


def test_threat_intelligence_lookup(tmp_path):
    ti = ThreatIntel(cache_file=tmp_path / "test_cache.json")
    res_bad = ti.lookup("http://account-verify.xyz/login")
    assert res_bad["reputation"] == "malicious"
    assert res_bad["feed_hit"] is True

    res_good = ti.lookup("https://github.com/login")
    assert res_good["reputation"] == "trusted"


def test_psi_drift_calculation():
    expected = [0.15] * 50 + [0.85] * 50
    # No drift
    actual_similar = [0.16] * 50 + [0.84] * 50
    res_stable = calculate_psi(expected, actual_similar)
    assert res_stable["drift_detected"] is False
    assert res_stable["psi"] < 0.25

    # Extreme shift (all high risk)
    actual_drift = [0.95] * 100
    res_drift = calculate_psi(expected, actual_drift)
    assert res_drift["drift_detected"] is True
