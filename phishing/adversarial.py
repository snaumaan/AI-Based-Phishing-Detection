"""Safe synthetic perturbations for evaluating model robustness and sensitivity."""
from .model import predict_text


def synthetic_variants(input_type: str, text: str) -> list[tuple[str, str]]:
    variants = [("Original Input", text)]
    if input_type == "URL":
        variants.append(("Benign Path Extension", text.rstrip("/") + "/about/security-overview"))
        variants.append(("Referral Query Parameter", text + ("&" if "?" in text else "?") + "ref=verified_partner"))
        variants.append(("Subdomain Prepend", text.replace("://", "://portal.safe-gateway.")))
    else:
        variants.append(("Benign Footer Padding", text + "\n\n--\nOfficial Communications Notice."))
        variants.append(("Softened Urgency Cues", text.replace("urgent", "important").replace("immediately", "when convenient").replace("now", "at your convenience")))
        variants.append(("Polite Salutation", "Dear Colleague,\n\n" + text))
    return variants


def run_simulation(input_type: str, text: str, bundle=None) -> list[dict]:
    rows = []
    for name, variant in synthetic_variants(input_type, text):
        result = predict_text(input_type, variant, bundle=bundle, log_to_mlops=False)
        rows.append({
            "variant": name,
            "text": variant,
            "prediction": result["verdict"],
            "risk_score": result["risk_score"],
            "risk_percentage": result["risk_percentage"],
            "confidence": result["confidence"],
            "latency_ms": result["latency_ms"]
        })
    return rows
