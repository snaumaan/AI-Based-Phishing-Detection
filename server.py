"""
PhishGuard - Flask Web Server
Serves the HTML/CSS/JS frontend and exposes REST API endpoints.
"""

import json
import os
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

app = Flask(__name__)

# Load model once at startup
from phishing.model import load_model, predict_text

try:
    _bundle = load_model()
    print("[server] Model loaded from disk.")
except Exception as exc:
    print(f"[server] Could not load saved model ({exc}). Run python train_model.py first.")
    _bundle = None

from phishing.mlops import get_mlops
mlops = get_mlops()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _load_json(path: Path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path: Path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# API – Scan
# ---------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():
    body = request.get_json(force=True)
    text = (body.get("text") or "").strip()
    input_type = (body.get("input_type") or "auto").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400
    itype_lower = input_type.lower()
    if itype_lower == "auto":
        # Simple auto-detect: URL vs Email (accept any email format)
        low = text.lower()
        if low.startswith("http://") or low.startswith("https://") or low.startswith("www."):
            input_type = "URL"
        else:
            input_type = "Email"
    elif itype_lower in ("url", "uri"):
        input_type = "URL"
    else:
        input_type = "Email"

    t0 = time.perf_counter()
    try:
        result = predict_text(input_type, text, bundle=_bundle)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)

    # Persist to scan history
    history = _load_json(DATA_DIR / "scan_history.json", [])
    history.insert(0, {
        "scan_id": result.get("scan_id", ""),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_preview": text[:80],
        "verdict": result.get("verdict", ""),
        "risk_percentage": result.get("risk_percentage", 0),
        "confidence": str(result.get("confidence", "")),
        "latency_ms": result.get("latency_ms", 0),
    })
    _save_json(DATA_DIR / "scan_history.json", history[:200])

    return jsonify(result)


# ---------------------------------------------------------------------------
# API – Batch
# ---------------------------------------------------------------------------

@app.route("/api/batch", methods=["POST"])
def api_batch():
    body = request.get_json(force=True)
    items = body.get("items") or []
    if not items:
        return jsonify({"error": "No items provided"}), 400

    results = []
    for item in items[:50]:
        text = (item if isinstance(item, str) else str(item)).strip()
        if not text:
            continue
        low = text.lower()
        if low.startswith("http://") or low.startswith("https://") or low.startswith("www."):
            itype = "URL"
        else:
            itype = "Email"
        try:
            r = predict_text(itype, text, bundle=_bundle)
            results.append({
                "input_preview": text[:80],
                "verdict": r.get("verdict", ""),
                "risk_percentage": r.get("risk_percentage", 0),
                "confidence": str(r.get("confidence", "")),
                "latency_ms": r.get("latency_ms", 0),
            })
        except Exception as exc:
            results.append({"input_preview": text[:80], "error": str(exc)})

    return jsonify({"results": results, "count": len(results)})


# ---------------------------------------------------------------------------
# API – History
# ---------------------------------------------------------------------------

@app.route("/api/history", methods=["GET"])
def api_history():
    history = _load_json(DATA_DIR / "scan_history.json", [])
    return jsonify(history[:100])


# ---------------------------------------------------------------------------
# API – Metrics
# ---------------------------------------------------------------------------

@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    metrics = _load_json(MODELS_DIR / "evaluation.json", {})
    return jsonify(metrics)


# ---------------------------------------------------------------------------
# API – Feedback
# ---------------------------------------------------------------------------

@app.route("/api/feedback", methods=["GET", "POST"])
def api_feedback():
    if request.method == "POST":
        body = request.get_json(force=True, silent=True) or {}
        scan_id = (body.get("scan_id") or "").strip()
        ground_truth = (body.get("ground_truth") or "").strip()
        analyst_notes = (body.get("analyst_notes") or "").strip()
        
        path = DATA_DIR / "analyst_feedback.json"
        feedback = _load_json(path, [])
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scan_id": scan_id,
            "ground_truth": ground_truth,
            "analyst_notes": analyst_notes
        }
        feedback.insert(0, entry)
        _save_json(path, feedback[:200])

        try:
            gt_int = 1 if ground_truth.lower() in ("phishing", "1", "true") else 0
            mlops.record_feedback(
                scan_id=scan_id,
                input_type="auto",
                text="",
                model_score=0.0,
                ground_truth=gt_int,
                analyst_notes=analyst_notes
            )
        except Exception:
            pass

        return jsonify({"status": "feedback recorded", "entry": entry})

    feedback = _load_json(DATA_DIR / "analyst_feedback.json", [])
    return jsonify(feedback)


@app.route("/api/learn", methods=["POST"])
def api_learn():
    body = request.get_json(force=True)
    raw_type = (body.get("input_type") or "Email").strip()
    input_type = "URL" if raw_type.lower() in ("url", "uri") else "Email"
    text = (body.get("text") or "").strip()
    ground_truth = (body.get("ground_truth") or "").strip()
    if not text or not ground_truth:
        return jsonify({"error": "text and ground_truth required"}), 400
    # Store the new sample for future offline retraining
    path = DATA_DIR / "online_samples.json"
    samples = _load_json(path, [])
    samples.append({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_type": input_type,
        "text": text,
        "ground_truth": ground_truth
    })
    _save_json(path, samples)
    return jsonify({"status": "sample recorded for incremental learning"})


# ---------------------------------------------------------------------------
# API – Threat Intel
# ---------------------------------------------------------------------------

@app.route("/api/threat-intel", methods=["GET"])
def api_threat_intel():
    cache = _load_json(DATA_DIR / "threat_intel_cache.json", {})
    return jsonify(cache)


# ---------------------------------------------------------------------------
# Error Handlers (Ensure all /api/ endpoints return JSON, never HTML)
# ---------------------------------------------------------------------------

@app.errorhandler(400)
def handle_400(err):
    return jsonify({"error": "Bad request", "details": str(err)}), 400

@app.errorhandler(404)
def handle_404(err):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Endpoint not found"}), 404
    return render_template("index.html")

@app.errorhandler(405)
def handle_405(err):
    return jsonify({"error": "Method not allowed for this endpoint"}), 405

@app.errorhandler(500)
def handle_500(err):
    return jsonify({"error": "Internal server error", "details": str(err)}), 500


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[server] PhishGuard running at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
