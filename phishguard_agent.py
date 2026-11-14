"""PhishGuard Agent (Module-2) — Standalone Tkinter Cybersecurity Client.

Provides local multi-vector scanning, Tiered Explainability (XAI),
scan history, and an analyst feedback loop with zero network dependencies.
"""
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime

from phishing.model import predict_text, load_model
from phishing.mlops import get_mlops


class PhishGuardApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PhishGuard AI — Multi-Vector Desktop Agent")
        self.root.geometry("980x680")
        self.root.minsize(800, 550)

        # Apply modern ttk theme
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.mlops = get_mlops()
        self.bundle = None
        self.current_result = None

        self._load_engine()
        self._build_ui()

    def _load_engine(self):
        try:
            self.bundle = load_model()
        except Exception as exc:
            messagebox.showwarning(
                "Model Warning",
                f"Model file not loaded: {exc}\nPlease run train_model.py. Predictions will attempt on-demand loading."
            )

    def _build_ui(self):
        # Header banner
        header = tk.Frame(self.root, bg="#101b33", height=60)
        header.pack(fill=tk.X, side=tk.TOP)
        title_lbl = tk.Label(
            header,
            text="PhishGuard: Multi-Vector Desktop Agent",
            font=("Segoe UI", 14, "bold"),
            fg="white",
            bg="#101b33"
        )
        title_lbl.pack(side=tk.LEFT, padx=16, pady=12)

        subtitle_lbl = tk.Label(
            header,
            text="Offline Engine · Calibrated Stacking · Tiered XAI",
            font=("Segoe UI", 9),
            fg="#90caf9",
            bg="#101b33"
        )
        subtitle_lbl.pack(side=tk.RIGHT, padx=16, pady=14)

        # Tab notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        self.scan_frame = ttk.Frame(self.notebook, padding=12)
        self.history_frame = ttk.Frame(self.notebook, padding=12)
        self.insights_frame = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.scan_frame, text="  Live Scanner  ")
        self.notebook.add(self.history_frame, text="  Scan History  ")
        self.notebook.add(self.insights_frame, text="  System Telemetry & Drift  ")

        self._build_scan_tab()
        self._build_history_tab()
        self._build_insights_tab()

    # ==================== SCAN TAB ====================
    def _build_scan_tab(self):
        # Input selection row
        ctrl_frame = ttk.Frame(self.scan_frame)
        ctrl_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(ctrl_frame, text="Input Vector:", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        self.input_type_var = tk.StringVar(value="URL")
        type_cb = ttk.Combobox(
            ctrl_frame,
            textvariable=self.input_type_var,
            values=["URL", "Email"],
            state="readonly",
            width=10
        )
        type_cb.pack(side=tk.LEFT, padx=(0, 15))

        load_btn = ttk.Button(ctrl_frame, text="Load Example", command=self._load_sample)
        load_btn.pack(side=tk.LEFT, padx=(0, 10))

        clear_btn = ttk.Button(ctrl_frame, text="Clear", command=lambda: self.input_text.delete("1.0", tk.END))
        clear_btn.pack(side=tk.LEFT)

        # Text area
        ttk.Label(self.scan_frame, text="Paste URL or Email Content (any format: body, headers, raw text):").pack(anchor=tk.W, pady=(4, 2))
        self.input_text = scrolledtext.ScrolledText(self.scan_frame, height=7, font=("Consolas", 10))
        self.input_text.pack(fill=tk.X, pady=(0, 8))

        # Scan button
        scan_btn = tk.Button(
            self.scan_frame,
            text="Analyze Content",
            font=("Segoe UI", 10, "bold"),
            bg="#1976d2",
            fg="white",
            relief=tk.FLAT,
            padx=20,
            pady=6,
            command=self._run_scan
        )
        scan_btn.pack(anchor=tk.W, pady=(0, 10))

        # Result display container
        self.res_card = tk.LabelFrame(self.scan_frame, text="Analysis Results", font=("Segoe UI", 10, "bold"), padx=12, pady=10)
        self.res_card.pack(fill=tk.BOTH, expand=True)

        # Tier 1 Banner
        self.verdict_lbl = tk.Label(
            self.res_card,
            text="Ready — Paste an input above and click 'Analyze Content'.",
            font=("Segoe UI", 12, "bold"),
            fg="#455a64"
        )
        self.verdict_lbl.pack(anchor=tk.W, pady=(0, 6))

        self.details_lbl = tk.Label(
            self.res_card,
            text="Tier 1: Calibrated Risk Score | Engine Latency",
            font=("Segoe UI", 9),
            fg="#546e7a"
        )
        self.details_lbl.pack(anchor=tk.W, pady=(0, 8))

        # Paned view for Tier 2 and Tier 3
        panes = ttk.PanedWindow(self.res_card, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, pady=4)

        # Left pane: Tier 2 Attributions
        left_box = ttk.LabelFrame(panes, text="Tier 2: Model Feature Attributions (XAI)", padding=6)
        panes.add(left_box, weight=1)

        self.tier2_text = scrolledtext.ScrolledText(left_box, height=8, font=("Consolas", 9))
        self.tier2_text.pack(fill=tk.BOTH, expand=True)

        # Right pane: Tier 3 Heuristics & Threat Intel
        right_box = ttk.LabelFrame(panes, text="Tier 3: Security Cues & Threat Intel", padding=6)
        panes.add(right_box, weight=1)

        self.tier3_text = scrolledtext.ScrolledText(right_box, height=8, font=("Segoe UI", 9))
        self.tier3_text.pack(fill=tk.BOTH, expand=True)

        # Feedback actions
        fb_frame = ttk.Frame(self.scan_frame)
        fb_frame.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(fb_frame, text="Analyst Feedback Loop:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        self.btn_confirm_phish = ttk.Button(
            fb_frame, text="Confirm Phishing", command=lambda: self._submit_feedback(1), state=tk.DISABLED
        )
        self.btn_confirm_phish.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_mark_safe = ttk.Button(
            fb_frame, text="Mark Safe (False Positive)", command=lambda: self._submit_feedback(0), state=tk.DISABLED
        )
        self.btn_mark_safe.pack(side=tk.LEFT)

    def _load_sample(self):
        samples = {
            "URL": "http://secure-login.bank-update.xyz/verify-account?ref=urgent",
            "Email": "URGENT: Your account has been suspended due to unauthorized access. Confirm credentials immediately at http://login.bank-update.xyz"
        }
        self.input_text.delete("1.0", tk.END)
        self.input_text.insert(tk.END, samples.get(self.input_type_var.get(), ""))

    def _run_scan(self):
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please paste content or load an example before analyzing.")
            return

        try:
            res = predict_text(self.input_type_var.get(), text, bundle=self.bundle)
            self.current_result = res

            # Update Tier 1
            color_map = {"red": "#c62828", "orange": "#e65100", "green": "#2e7d32"}
            fg = color_map.get(res["verdict_color"], "#333333")
            self.verdict_lbl.config(
                text=f"Verdict: {res['verdict']} — {res['risk_percentage']}% Risk",
                fg=fg
            )
            self.details_lbl.config(
                text=f"Confidence: {res['confidence']} | Engine Execution: {res['latency_ms']} ms | Scan ID: {res['scan_id']}"
            )

            # Update Tier 2 (Attributions)
            self.tier2_text.delete("1.0", tk.END)
            if res["tier2_attributions"]:
                self.tier2_text.insert(tk.END, f"{'Feature':<22} | {'Value':<6} | {'Contribution'}\n")
                self.tier2_text.insert(tk.END, "-" * 48 + "\n")
                for item in res["tier2_attributions"][:8]:
                    arrow = "▲" if item["contribution"] > 0 else "▼"
                    self.tier2_text.insert(
                        tk.END,
                        f"{item['feature']:<22} | {item['value']:<6.1f} | {arrow} {item['contribution']:+.3f} ({item['direction']})\n"
                    )
            else:
                self.tier2_text.insert(tk.END, "Neutral feature weights detected.")

            # Update Tier 3 (Heuristics & Threat Intel)
            self.tier3_text.delete("1.0", tk.END)
            for h in res["tier3_heuristics"]:
                self.tier3_text.insert(tk.END, f"• {h}\n")

            # Enable feedback buttons
            self.btn_confirm_phish.config(state=tk.NORMAL)
            self.btn_mark_safe.config(state=tk.NORMAL)

            # Refresh history & insights tabs
            self._refresh_history()
            self._refresh_insights()

        except Exception as exc:
            messagebox.showerror("Scan Error", f"Failed to complete scan:\n{exc}")

    def _submit_feedback(self, ground_truth: int):
        if not self.current_result:
            return
        res = self.current_result
        self.mlops.record_feedback(
            scan_id=res["scan_id"],
            input_type=res["input_type"],
            text=self.input_text.get("1.0", tk.END).strip(),
            model_score=res["risk_score"],
            ground_truth=ground_truth,
            analyst_notes="Logged via PhishGuard Desktop Client"
        )
        status = "Confirmed Phishing" if ground_truth == 1 else "Marked Safe"
        messagebox.showinfo("Feedback Recorded", f"Analyst feedback saved: {status}.\nUpdated MLOps metrics.")
        self.btn_confirm_phish.config(state=tk.DISABLED)
        self.btn_mark_safe.config(state=tk.DISABLED)
        self._refresh_insights()

    # ==================== HISTORY TAB ====================
    def _build_history_tab(self):
        top_bar = ttk.Frame(self.history_frame)
        top_bar.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(top_bar, text="Recent Local Scans", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        ttk.Button(top_bar, text="Refresh", command=self._refresh_history).pack(side=tk.RIGHT)

        cols = ("Timestamp", "Vector", "Risk Score", "Verdict", "Latency", "Snippet")
        self.history_tree = ttk.Treeview(self.history_frame, columns=cols, show="headings", height=16)

        self.history_tree.heading("Timestamp", text="Timestamp")
        self.history_tree.heading("Vector", text="Vector")
        self.history_tree.heading("Risk Score", text="Risk Score")
        self.history_tree.heading("Verdict", text="Verdict")
        self.history_tree.heading("Latency", text="Latency")
        self.history_tree.heading("Snippet", text="Snippet")

        self.history_tree.column("Timestamp", width=140)
        self.history_tree.column("Vector", width=70)
        self.history_tree.column("Risk Score", width=90)
        self.history_tree.column("Verdict", width=150)
        self.history_tree.column("Latency", width=75)
        self.history_tree.column("Snippet", width=360)

        self.history_tree.pack(fill=tk.BOTH, expand=True)
        self._refresh_history()

    def _refresh_history(self):
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)
        for entry in self.mlops.history[:50]:
            self.history_tree.insert(
                "",
                tk.END,
                values=(
                    entry["timestamp"],
                    entry["input_type"],
                    f"{round(entry['risk_score'] * 100, 1)}%",
                    entry["verdict"],
                    f"{entry['latency_ms']} ms",
                    entry["snippet"]
                )
            )

    # ==================== INSIGHTS TAB ====================
    def _build_insights_tab(self):
        ttk.Label(self.insights_frame, text="Continuous Learning & Drift Telemetry", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # Stats frame
        self.stats_box = ttk.LabelFrame(self.insights_frame, text="Analyst Feedback Loop & Gated Promotion", padding=12)
        self.stats_box.pack(fill=tk.X, pady=(0, 12))

        self.lbl_feedback_stats = ttk.Label(self.stats_box, text="Loading feedback metrics...", font=("Segoe UI", 10))
        self.lbl_feedback_stats.pack(anchor=tk.W)

        # Drift frame
        self.drift_box = ttk.LabelFrame(self.insights_frame, text="Data Distribution Drift Monitor (Population Stability Index)", padding=12)
        self.drift_box.pack(fill=tk.BOTH, expand=True)

        self.lbl_drift_status = ttk.Label(self.drift_box, text="Evaluating PSI drift...", font=("Segoe UI", 10))
        self.lbl_drift_status.pack(anchor=tk.W, pady=(0, 8))

        self.drift_text = scrolledtext.ScrolledText(self.drift_box, height=10, font=("Consolas", 9))
        self.drift_text.pack(fill=tk.BOTH, expand=True)

        self._refresh_insights()

    def _refresh_insights(self):
        fb = self.mlops.get_feedback_metrics()
        self.lbl_feedback_stats.config(
            text=f"Total Analyst Reviews: {fb['total_reviews']}  |  Agreement Accuracy: {fb['accuracy'] * 100:.1f}%\n"
                 f"Confirmed Phishing: {fb['confirmed_phish']}  |  False Alarms: {fb['false_alarms']}\n"
                 f"Model Update Gate: {fb['gate_status']}"
        )

        drift = self.mlops.get_drift_status()
        self.lbl_drift_status.config(
            text=f"Current PSI Index: {drift['psi']}  |  Health: {drift['status']}"
        )

        self.drift_text.delete("1.0", tk.END)
        if drift["bin_details"]:
            self.drift_text.insert(tk.END, f"{'Score Bin':<12} | {'Baseline %':<12} | {'Recent %':<12} | {'PSI Contribution'}\n")
            self.drift_text.insert(tk.END, "-" * 56 + "\n")
            for b in drift["bin_details"]:
                self.drift_text.insert(
                    tk.END,
                    f"{b['bin']:<12} | {b['expected_pct']:<12.1f} | {b['actual_pct']:<12.1f} | {b['psi_contribution']:+.4f}\n"
                )
        else:
            self.drift_text.insert(tk.END, "Collecting live scan scores. Once 5+ scans are recorded, PSI binning activates.")


def main():
    root = tk.Tk()
    app = PhishGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
