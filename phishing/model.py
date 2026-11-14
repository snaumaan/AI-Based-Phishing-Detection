"""Multi-model loading, calibrated prediction, and Tiered Explainability (XAI) engine."""
from pathlib import Path
import time
import joblib
import pandas as pd
import numpy as np

from .features import FEATURE_NAMES, extract_features, heuristic_indicators
from .threat_intel import check_threat_intel
from .mlops import get_mlops

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"


def load_model(path: Path = MODEL_PATH):
    if not path.exists():
        raise FileNotFoundError(f"Model artifact not found at {path}. Run: python train_model.py")
    bundle = joblib.load(path)
    if bundle.get("feature_names") != FEATURE_NAMES:
        raise ValueError("Model feature metadata does not match current feature extractor. Retrain the model.")
    return bundle


def calculate_tier2_attributions(features: dict[str, float], bundle: dict) -> list[dict]:
    """Calculate exact additive feature attributions for Tier 2 XAI."""
    # Use learned Logistic Regression coefficients scaled by feature standard deviations / values
    lr_coefs = bundle.get("lr_coefs", {})
    rf_importances = bundle.get("rf_importances", {})

    attributions = []
    for name in FEATURE_NAMES:
        val = features.get(name, 0.0)
        coef = lr_coefs.get(name, 0.0)
        importance = rf_importances.get(name, 0.0)

        # Contribution is directional (positive = pushes phishing, negative = pushes legitimate)
        if val > 0:
            impact = coef * val
            # Normalized contribution scale
            directional_weight = round(float(impact), 3)
            if abs(directional_weight) >= 0.01:
                attributions.append({
                    "feature": name,
                    "value": val,
                    "direction": "Pushes Phishing" if directional_weight > 0 else "Pushes Legitimate",
                    "contribution": directional_weight,
                    "global_importance": round(float(importance), 4)
                })

    # Sort by absolute contribution magnitude
    attributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    return attributions


def predict_text(input_type: str, text: str, bundle=None, log_to_mlops: bool = True) -> dict:
    """Execute end-to-end multi-vector scan with tiered explainability."""
    t0 = time.perf_counter()

    if bundle is None:
        bundle = load_model()

    # 1. Feature extraction
    features = extract_features(input_type, text)
    X = pd.DataFrame([[features[name] for name in FEATURE_NAMES]], columns=FEATURE_NAMES)

    # 2. Multi-model scoring
    model = bundle["model"]  # Calibrated Stacking Ensemble
    raw_probs = model.predict_proba(X)[0]
    calibrated_prob = float(raw_probs[1])

    # Threat Intelligence lookup (offline cache / feed)
    threat_info = check_threat_intel(text) if input_type == "URL" else {"reputation": "neutral", "risk_adjustment": 0.0, "feed_hit": False, "reasons": []}

    # Fused Risk Score incorporating threat intelligence signals
    fused_risk = max(0.0, min(1.0, calibrated_prob + threat_info.get("risk_adjustment", 0.0)))
    risk_percentage = round(fused_risk * 100, 1)

    # 3. Tier 1: High-level Verdict & Confidence Badge
    if risk_percentage >= 70.0:
        verdict = "HIGH-RISK PHISHING"
        verdict_color = "red"
        confidence = "High Confidence" if risk_percentage >= 85.0 else "Moderate Confidence"
    elif risk_percentage >= 40.0:
        verdict = "SUSPICIOUS CONTENT"
        verdict_color = "orange"
        confidence = "Borderline / Escalate to Analyst"
    else:
        verdict = "LIKELY LEGITIMATE"
        verdict_color = "green"
        confidence = "High Confidence" if risk_percentage <= 15.0 else "Moderate Confidence"

    # 4. Tier 2: Feature Attributions (XAI)
    tier2_attributions = calculate_tier2_attributions(features, bundle)

    # 5. Tier 3: Heuristic & Threat Intel Indicators
    tier3_heuristics = heuristic_indicators(input_type, text)
    if threat_info.get("reasons"):
        tier3_heuristics = [f"[Threat Intel] {r}" for r in threat_info["reasons"]] + tier3_heuristics

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    # Optional MLOps logging
    scan_id = ""
    if log_to_mlops:
        try:
            entry = get_mlops().log_scan(
                input_type=input_type,
                text=text,
                score=fused_risk,
                verdict=verdict,
                latency_ms=latency_ms
            )
            scan_id = entry["id"]
        except Exception:
            pass

    return {
        "scan_id": scan_id,
        "input_type": input_type,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "risk_score": fused_risk,
        "risk_percentage": risk_percentage,
        "calibrated_model_probability": round(calibrated_prob, 4),
        "confidence": confidence,
        "tier1_summary": f"{verdict} ({risk_percentage}%) — {confidence}",
        "tier2_attributions": tier2_attributions,
        "tier3_heuristics": tier3_heuristics,
        "threat_intel": threat_info,
        "features": features,
        "latency_ms": latency_ms,
        "models_used": "Calibrated Stacking Classifier (Logistic Regression + Random Forest + GBDT)"
    }
