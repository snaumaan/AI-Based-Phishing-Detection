"""Train and evaluate Multi-Model Ensemble (LR, Random Forest, GBDT, Stacking) with Calibration."""
from pathlib import Path
import json
import joblib
import pandas as pd
import numpy as np

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, StackingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, brier_score_loss, confusion_matrix, classification_report,
    roc_curve, precision_recall_curve
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from phishing.features import FEATURE_NAMES
from phishing.dataset import build_dataset, SEED

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "sample_dataset.csv"
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"
METRICS_PATH = ROOT / "models" / "evaluation.json"
BASELINE_PATH = ROOT / "data" / "baseline_distribution.json"


def evaluate_model(clf, X_test, y_test, model_name: str) -> dict:
    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1] if hasattr(clf, "predict_proba") else preds

    fpr, tpr, _ = roc_curve(y_test, probs)
    precision_vals, recall_vals, _ = precision_recall_curve(y_test, probs)

    return {
        "model_name": model_name,
        "accuracy": float(accuracy_score(y_test, preds)),
        "precision": float(precision_score(y_test, preds, zero_division=0)),
        "recall": float(recall_score(y_test, preds, zero_division=0)),
        "f1": float(f1_score(y_test, preds, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probs)),
        "brier_score": float(brier_score_loss(y_test, probs)),
        "confusion_matrix": confusion_matrix(y_test, preds, labels=[0, 1]).tolist(),
        "roc_curve": {
            "fpr": [round(float(x), 4) for x in fpr],
            "tpr": [round(float(x), 4) for x in tpr]
        },
        "pr_curve": {
            "precision": [round(float(x), 4) for x in precision_vals],
            "recall": [round(float(x), 4) for x in recall_vals]
        }
    }


def main():
    ROOT.joinpath("data").mkdir(exist_ok=True)
    ROOT.joinpath("models").mkdir(exist_ok=True)

    print("Building fresh multi-vector dataset...")
    df = build_dataset()
    df.to_csv(DATA_PATH, index=False)
    print(f"Dataset generated: {len(df)} rows across {df['group_id'].nunique()} template groups.")

    required = {"input_type", "text", "label", "group_id", *FEATURE_NAMES}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing columns: {sorted(missing)}")

    # Split template groups, not individual rows, to eliminate near-duplicate leakage
    groups = df[["group_id", "input_type", "label"]].drop_duplicates("group_id")
    groups["stratum"] = groups["input_type"] + "_" + groups["label"].astype(str)
    train_groups, test_groups = train_test_split(
        groups["group_id"], test_size=0.25, random_state=SEED,
        stratify=groups["stratum"]
    )

    train_df = df[df["group_id"].isin(set(train_groups))].copy()
    test_df = df[df["group_id"].isin(set(test_groups))].copy()

    X_train, y_train = train_df[FEATURE_NAMES], train_df["label"].astype(int)
    X_test, y_test = test_df[FEATURE_NAMES], test_df["label"].astype(int)

    print(f"Training split: {len(train_df)} rows | Test split: {len(test_df)} rows")

    # 1. Logistic Regression Baseline
    print("Training 1/4: Logistic Regression...")
    lr_pipe = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED))
    lr_pipe.fit(X_train, y_train)

    # 2. Random Forest Classifier
    print("Training 2/4: Random Forest Classifier...")
    rf_clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=SEED, class_weight="balanced")
    rf_clf.fit(X_train, y_train)

    # 3. Gradient Boosting Classifier
    print("Training 3/4: Gradient Boosting Classifier...")
    gb_clf = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=4, random_state=SEED)
    gb_clf.fit(X_train, y_train)

    # 4. Stacking Classifier with Calibration
    print("Training 4/4: Calibrated Stacking Classifier Ensemble...")
    base_estimators = [
        ("lr", make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=SEED))),
        ("rf", RandomForestClassifier(n_estimators=60, max_depth=8, random_state=SEED)),
        ("gb", GradientBoostingClassifier(n_estimators=60, learning_rate=0.1, max_depth=3, random_state=SEED))
    ]
    stacking_base = StackingClassifier(
        estimators=base_estimators,
        final_estimator=LogisticRegression(),
        cv=3
    )
    # Calibrate probabilities using Platt scaling (sigmoid calibration)
    calibrated_stacking = CalibratedClassifierCV(stacking_base, method="sigmoid", cv=3)
    calibrated_stacking.fit(X_train, y_train)

    # Evaluate all models
    models_evaluated = {
        "Logistic Regression": evaluate_model(lr_pipe, X_test, y_test, "Logistic Regression (Baseline)"),
        "Random Forest": evaluate_model(rf_clf, X_test, y_test, "Random Forest (Bagging Ensemble)"),
        "Gradient Boosting": evaluate_model(gb_clf, X_test, y_test, "Gradient Boosting (GBDT)"),
        "Stacking Ensemble": evaluate_model(calibrated_stacking, X_test, y_test, "Calibrated Stacking Ensemble (Production)")
    }

    # Extract feature importances (from Random Forest & LR) for Tier 2 XAI
    rf_importances = dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in rf_clf.feature_importances_]))
    lr_coefs = dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in lr_pipe.named_steps["logisticregression"].coef_[0]]))

    # Overall evaluation payload
    metrics = {
        "dataset_note": "Multi-Vector Synthetic Educational Dataset (URL, Email, HTML). Authored for research prototype.",
        "seed": SEED,
        "rows_total": int(len(df)),
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "train_groups": int(train_df["group_id"].nunique()),
        "test_groups": int(test_df["group_id"].nunique()),
        "class_counts_total": {str(k): int(v) for k, v in df["label"].value_counts().sort_index().items()},
        "class_counts_test": {str(k): int(v) for k, v in y_test.value_counts().sort_index().items()},
        "models": models_evaluated,
        "feature_importances": rf_importances,
        "feature_coefficients": lr_coefs,
        "production_model": "Stacking Ensemble",
        "limitations": "Model evaluation reflects the held-out template split. Zero-day campaigns with brand new unseen structural patterns may require continuous analyst feedback and retrained models."
    }

    # Save baseline distribution for MLOps drift monitoring
    test_scores = calibrated_stacking.predict_proba(X_test)[:, 1].tolist()
    BASELINE_PATH.write_text(json.dumps([round(float(s), 4) for s in test_scores], indent=2))

    # Save model bundle
    bundle = {
        "model": calibrated_stacking,
        "lr_model": lr_pipe,
        "rf_model": rf_clf,
        "gb_model": gb_clf,
        "feature_names": FEATURE_NAMES,
        "seed": SEED,
        "rf_importances": rf_importances,
        "lr_coefs": lr_coefs,
        "dataset_note": metrics["dataset_note"],
        "model_name": "Calibrated Stacking Classifier (LR + RF + GBDT)"
    }
    joblib.dump(bundle, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))

    print(f"\n==================== TRAINING SUMMARY ====================")
    print(f"Saved Production Model: {MODEL_PATH}")
    print(f"Saved Evaluation Suite: {METRICS_PATH}")
    print(f"{'Model':<25} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'ROC-AUC':<10}")
    print("-" * 85)
    for name, m in models_evaluated.items():
        print(f"{name:<25} | {m['accuracy']:<10.3f} | {m['precision']:<10.3f} | {m['recall']:<10.3f} | {m['f1']:<10.3f} | {m['roc_auc']:<10.3f}")
    print("==========================================================")


if __name__ == "__main__":
    main()
