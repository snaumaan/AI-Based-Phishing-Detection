# PhishGuard AI – Multi‑Vector, Explainable Phishing Detection

A comprehensive, offline‑first phishing detection engine that works on **URLs and Email / Text content (with unrestricted email formats)**. It ships with **two user interfaces**:

1. **Web UI** – a modern Flask‑based single‑page app (`http://localhost:5000`).
2. **Desktop client** – a native Tkinter application (`phishguard_agent.py`).

Both interfaces share the same calibrated stacking model, data files, and MLOps utilities, so scans, feedback, and online‑learning samples are stored in a single JSON‑based “database”.

---

## Project Structure

```text
phishing_detection_poc/
├─ server.py                     # Flask web server + API endpoints
├─ app.py                         # (deprecated) old Streamlit dashboard – can be removed
├─ phishguard_agent.py            # Tkinter desktop client
├─ phishguard_engine.py           # Core detection engine
├─ train_model.py                 # Model training / evaluation script
├─ requirements.txt               # Python dependencies
├─ README.md                      # This file
├─ data/
│   ├─ sample_dataset.csv          # Synthetic training data (480 rows)
│   ├─ threat_intel_cache.json     # Offline domain reputation cache
│   ├─ baseline_distribution.json  # Baseline scores for PSI drift monitoring
│   ├─ scan_history.json           # Log of all scans (web & desktop)
│   ├─ analyst_feedback.json       # Analyst‑provided ground‑truth feedback
│   └─ online_samples.json         # Samples submitted via the /api/learn endpoint
├─ models/
│   ├─ phishing_model.joblib       # Calibrated stacking ensemble bundle
│   └─ evaluation.json             # Benchmark metrics (ROC‑AUC, confusion matrix…)
├─ phishing/
│   ├─ __init__.py
│   ├─ features.py                 # 28‑feature extractor & heuristics
│   ├─ dataset.py                  # Deterministic synthetic data generator
│   ├─ model.py                    # Prediction engine + Tier‑2 XAI attribution
│   ├─ threat_intel.py             # Offline threat‑intel lookup
│   ├─ mlops.py                    # PSI drift calculation & feedback loop
│   ├─ few_shot.py                 # Few‑shot adaptation prototype
│   └─ adversarial.py              # Synthetic perturbation testing
├─ static/
│   ├─ css/style.css               # Dark‑theme stylesheet (no emojis)
│   └─ js/main.js                  # Front‑end logic – API calls, charts, feedback
├─ templates/
│   └─ index.html                  # Jinja2 template for the Flask UI
└─ tests/
    └─ test_phishing.py            # Automated test suite (all passing)
```

---

## Quickstart Guide

### 1. Set up the environment
```powershell
cd "D:\major project\PROJECT\phishing_detection_poc"
# Activate the virtual environment (PowerShell)
.\.venv\Scripts\Activate.ps1
```

### 2. Run the automated tests (recommended)
```bash
python -m pytest -q          # Run the pytest suite
python -m unittest test_engine.py   # Run the 16 engine unit‑tests
```
All tests should pass, confirming the detection engine works as expected.

### 3. Retrain / evaluate the model (optional)
```bash
python train_model.py
```
This will rebuild `models/phishing_model.joblib` and update `models/evaluation.json` with the latest benchmark numbers.

### 4. Launch the **Web UI** (Flask)
```bash
python server.py
```
You will see:
```
[server] Model loaded from disk.
[server] PhishGuard running at http://localhost:5000
```
Open a browser at **`http://localhost:5000`**.  The UI provides the following tabs:
- **Scanner** – paste a URL or email text (any format: body, headers, raw content) and get an immediate verdict with risk, confidence, feature attribution chart, and heuristic indicators.
- **Batch Analysis** – scan many lines at once, view a result table, and download a CSV.
- **Scan History** – view the most recent 100 scans stored in `data/scan_history.json`.
- **Model Metrics** – display the contents of `models/evaluation.json`.
- **Threat Intel** – explore the offline domain‑reputation cache.

#### New API endpoints (used by the UI)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Scan a single input. Returns the full prediction dict (verdict, risk %, confidence, tier‑2 attributions, etc.). |
| `POST` | `/api/batch` | Scan up to 50 items in one request. Returns a list of results.
| `GET`  | `/api/history` | Return the latest 100 entries from `scan_history.json`.
| `GET`  | `/api/metrics` | Return the benchmark JSON from `models/evaluation.json`.
| `GET`  | `/api/feedback` | Retrieve analyst feedback entries.
| `POST` | `/api/feedback` | Record a new feedback entry (`scan_id` + `ground_truth`).
| `GET`  | `/api/threat-intel` | Return the offline threat‑intel cache.
| `POST` | `/api/learn` | **New!** Store a user‑provided sample for incremental learning. Payload: `{"input_type":"URL|Email","text":"...","ground_truth":"phishing|legitimate"}`. The sample is appended to `data/online_samples.json` for later retraining.

### 5. Launch the **Desktop client** (Tkinter)
```bash
python phishguard_agent.py
```
The desktop app works completely offline and shares the same model and JSON data files as the web UI.  Scan results are automatically logged to `data/scan_history.json`.

#### Optional integration
If you prefer the desktop client **not** to load the model locally, you can modify `phishguard_agent.py` to call the Flask `/api/scan` endpoint instead.  This provides a single source of truth for the model and keeps all logs in the same place.

---

## Technical & Architectural Highlights

- **Multi‑Vector Feature Extraction** – 28 handcrafted lexical, entropy, punycode, and DOM‑form features.
- **Calibrated Stacking Ensemble** – Logistic Regression + Random Forest + Gradient Boosting with Platt scaling for reliable probability estimates.
- **Three‑Tier XAI**:
  - *Tier 1*: Verdict, risk %, confidence badge.
  - *Tier 2*: Directional feature attributions (displayed as a bar chart).
  - *Tier 3*: Heuristic indicators and offline threat‑intel cues.
- **Population Stability Index (PSI)** – Detects drift between live scan scores and the training baseline (`baseline_distribution.json`).
- **Analyst Feedback Loop** – Records ground‑truth confirmations, computes accuracy, and flags false‑alarm regression.
- **Incremental Learning Hook** – `/api/learn` stores new labeled samples (`online_samples.json`) for future model retraining without touching the codebase.
- **Zero Network Calls** – All threat‑intel lookups and model inference happen locally; the server never reaches out to external URLs.

---

## License & Contributions
This project is released under the **MIT License**.  Contributions are welcome – feel free to open a Pull Request or issue for bug fixes, new features (e.g., a FastAPI version), or additional threat‑intel feeds.

---

*Last updated: 2026‑11‑13*