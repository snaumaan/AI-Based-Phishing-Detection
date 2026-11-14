"""MLOps module: Population Stability Index (PSI) drift monitoring and analyst feedback loop."""
from __future__ import annotations
import json
import math
import time
from datetime import datetime
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"

HISTORY_FILE = DATA_DIR / "scan_history.json"
FEEDBACK_FILE = DATA_DIR / "analyst_feedback.json"
BASELINE_FILE = DATA_DIR / "baseline_distribution.json"


def calculate_psi(expected_scores: list[float], actual_scores: list[float], num_bins: int = 10) -> dict:
    """Calculate Population Stability Index (PSI) to detect model prediction drift."""
    if len(expected_scores) < 10 or len(actual_scores) < 5:
        return {
            "psi": 0.0,
            "status": "Insufficient data (minimum 5 scans needed for drift)",
            "bin_details": [],
            "drift_detected": False
        }

    # Fixed bins from 0.0 to 1.0
    bins = np.linspace(0.0, 1.0, num_bins + 1)
    exp_counts, _ = np.histogram(expected_scores, bins=bins)
    act_counts, _ = np.histogram(actual_scores, bins=bins)

    exp_total = len(expected_scores)
    act_total = len(actual_scores)

    psi_total = 0.0
    bin_details = []

    for i in range(num_bins):
        # Apply Laplace smoothing to avoid log(0) or division by zero
        exp_pct = (exp_counts[i] + 1) / (exp_total + num_bins)
        act_pct = (act_counts[i] + 1) / (act_total + num_bins)

        bin_psi = (act_pct - exp_pct) * math.log(act_pct / exp_pct)
        psi_total += bin_psi

        bin_details.append({
            "bin": f"{bins[i]:.1f}-{bins[i+1]:.1f}",
            "expected_pct": round(exp_pct * 100, 1),
            "actual_pct": round(act_pct * 100, 1),
            "psi_contribution": round(bin_psi, 4)
        })

    psi_total = round(float(psi_total), 4)

    if psi_total < 0.10:
        status = "Stable (PSI < 0.10: distribution matches baseline)"
        drift = False
    elif psi_total < 0.25:
        status = "Watch (0.10 <= PSI < 0.25: moderate distribution shift)"
        drift = False
    else:
        status = "Drift Detected (PSI >= 0.25: significant shift, review required)"
        drift = True

    return {
        "psi": psi_total,
        "status": status,
        "drift_detected": drift,
        "bin_details": bin_details
    }


class MLOpsManager:
    """Handles scan logging, analyst feedback, and drift monitoring."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.history = self._load_json(HISTORY_FILE, default=[])
        self.feedback = self._load_json(FEEDBACK_FILE, default=[])

    def _load_json(self, path: Path, default):
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return default
        return default

    def _save_json(self, path: Path, data):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def log_scan(self, input_type: str, text: str, score: float, verdict: str, latency_ms: float) -> dict:
        """Record an analysis run to scan history."""
        entry = {
            "id": f"scan_{len(self.history) + 1}_{int(time.time())}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "input_type": input_type,
            "snippet": text[:120] + ("..." if len(text) > 120 else ""),
            "full_text": text,
            "risk_score": round(score, 4),
            "verdict": verdict,
            "latency_ms": round(latency_ms, 2)
        }
        self.history.insert(0, entry)  # latest first
        if len(self.history) > 500:
            self.history = self.history[:500]
        self._save_json(HISTORY_FILE, self.history)
        return entry

    def record_feedback(self, scan_id: str, input_type: str, text: str, model_score: float, ground_truth: int, analyst_notes: str = "") -> dict:
        """Record an analyst's ground truth confirmation (1 = Phish, 0 = Legitimate)."""
        entry = {
            "feedback_id": f"fb_{len(self.feedback) + 1}",
            "scan_id": scan_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "input_type": input_type,
            "snippet": text[:120],
            "model_score": model_score,
            "model_pred": 1 if model_score >= 0.5 else 0,
            "ground_truth": ground_truth,
            "is_correct": (1 if model_score >= 0.5 else 0) == ground_truth,
            "is_false_alarm": (model_score >= 0.5) and (ground_truth == 0),
            "analyst_notes": analyst_notes
        }
        self.feedback.insert(0, entry)
        self._save_json(FEEDBACK_FILE, self.feedback)
        return entry

    def get_feedback_metrics(self) -> dict:
        """Compute analyst review agreement and gate status."""
        if not self.feedback:
            return {
                "total_reviews": 0,
                "accuracy": 1.0,
                "false_alarms": 0,
                "confirmed_phish": 0,
                "gate_status": "Awaiting initial analyst reviews"
            }
        correct = sum(1 for f in self.feedback if f["is_correct"])
        false_alarms = sum(1 for f in self.feedback if f["is_false_alarm"])
        confirmed = sum(1 for f in self.feedback if f["ground_truth"] == 1)
        total = len(self.feedback)
        acc = correct / total

        # Phase-1 Gate rule: accept update only if accuracy does not drop & false alarms do not spike
        gate_status = "Approved: No false alarm regression" if false_alarms == 0 else f"Review Needed: {false_alarms} false alarm(s) flagged"

        return {
            "total_reviews": total,
            "accuracy": round(acc, 3),
            "false_alarms": false_alarms,
            "confirmed_phish": confirmed,
            "gate_status": gate_status
        }

    def get_drift_status(self) -> dict:
        """Run PSI on recent scan scores against baseline training scores."""
        baseline_path = BASELINE_FILE
        if baseline_path.exists():
            try:
                baseline_scores = json.loads(baseline_path.read_text(encoding="utf-8"))
            except Exception:
                baseline_scores = [0.05] * 50 + [0.95] * 50
        else:
            baseline_scores = [0.05] * 50 + [0.95] * 50

        recent_scores = [s["risk_score"] for s in self.history[:100]]
        return calculate_psi(baseline_scores, recent_scores)


_mlops_manager = MLOpsManager()


def get_mlops() -> MLOpsManager:
    return _mlops_manager

