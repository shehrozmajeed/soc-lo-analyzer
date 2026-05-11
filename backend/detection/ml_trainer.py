"""
detection/ml_trainer.py
───────────────────────
Train, evaluate, and persist the SOC threat classification model.

Models trained (best selected):
  1. Random Forest Classifier     — robust, interpretable
  2. Gradient Boosted Trees       — highest accuracy
  3. Isolation Forest             — unsupervised anomaly fallback

Pipeline:
  load CSV → feature engineering → SMOTE oversampling → train/test split
  → train all models → evaluate → persist best model → export metrics
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_recall_fscore_support, roc_auc_score
)
from sklearn.pipeline import Pipeline

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET_CSV = os.path.join(BASE_DIR, "data", "training_dataset.csv")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
MODEL_PATH  = os.path.join(MODEL_DIR, "soc_classifier.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "model_metrics.json")
ISO_PATH    = os.path.join(MODEL_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)

# ── Feature columns ────────────────────────────────────────────────────────────
FEATURE_COLS = [
    "request_count", "error_4xx_count", "error_5xx_count",
    "unique_paths", "failed_logins", "bytes_sent_mean",
    "time_spread_secs", "login_attempts", "req_rate_per_sec",
    "has_sqli", "has_xss", "is_known_bad_ip",
    "distinct_ports", "ua_diversity",
]

ATTACK_LABELS = {
    0: "Normal",
    1: "Brute Force",
    2: "DDoS",
    3: "Port Scan",
    4: "SQL Injection",
    5: "XSS",
    6: "Privilege Escalation",
    7: "Insider Threat",
    8: "Bot Crawler",
    9: "APT Slow & Low",
}


def load_dataset():
    if not os.path.exists(DATASET_CSV):
        raise FileNotFoundError(
            f"Training dataset not found at {DATASET_CSV}. "
            "Run: python data/generate_dataset.py"
        )
    df = pd.read_csv(DATASET_CSV)
    logger.info("Loaded dataset: %d records, %d features", len(df), len(FEATURE_COLS))
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add derived features to improve model performance."""
    df = df.copy()

    # Ratio features
    df["error_ratio"] = (df["error_4xx_count"] + df["error_5xx_count"]) / (df["request_count"] + 1)
    df["login_fail_ratio"] = df["failed_logins"] / (df["login_attempts"] + 1)
    df["path_density"] = df["unique_paths"] / (df["request_count"] + 1)

    # Log-transformed features (handle zeros)
    df["log_request_count"]  = np.log1p(df["request_count"])
    df["log_bytes_mean"]     = np.log1p(df["bytes_sent_mean"])
    df["log_time_spread"]    = np.log1p(df["time_spread_secs"])
    df["log_req_rate"]       = np.log1p(df["req_rate_per_sec"])

    # Interaction features
    df["burst_score"] = df["req_rate_per_sec"] * df["error_ratio"]
    df["auth_attack_score"] = df["failed_logins"] * df["req_rate_per_sec"]

    return df


def get_feature_cols_extended():
    return FEATURE_COLS + [
        "error_ratio", "login_fail_ratio", "path_density",
        "log_request_count", "log_bytes_mean", "log_time_spread",
        "log_req_rate", "burst_score", "auth_attack_score",
    ]


def train():
    """Full training pipeline. Returns metrics dict."""
    logger.info("Starting SOC model training pipeline...")

    # ── Load & engineer ────────────────────────────────────────────────────
    df = load_dataset()
    df = engineer_features(df)

    feat_cols = get_feature_cols_extended()
    X = df[feat_cols].fillna(0).values
    y = df["label"].values

    logger.info("Class distribution: %s", dict(Counter(y)))

    # ── Scale ──────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Train/test split ───────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── Train models ───────────────────────────────────────────────────────
    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, max_depth=None,
            min_samples_split=2, class_weight="balanced",
            random_state=42, n_jobs=-1,
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=150, learning_rate=0.1,
            max_depth=5, random_state=42,
        ),
    }

    results = {}
    best_model = None
    best_score = 0.0

    for name, model in models.items():
        logger.info("Training %s...", name)
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        acc    = accuracy_score(y_test, y_pred)
        p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)

        # Cross-validation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X_scaled, y, cv=cv, scoring="f1_weighted")

        results[name] = {
            "accuracy":    round(acc, 4),
            "precision":   round(p, 4),
            "recall":      round(r, 4),
            "f1_weighted": round(f1, 4),
            "cv_f1_mean":  round(cv_scores.mean(), 4),
            "cv_f1_std":   round(cv_scores.std(), 4),
        }

        logger.info("%s: acc=%.4f f1=%.4f cv_f1=%.4f±%.4f",
                    name, acc, f1, cv_scores.mean(), cv_scores.std())

        if cv_scores.mean() > best_score:
            best_score = cv_scores.mean()
            best_model = (name, model)

    # ── Per-class report ───────────────────────────────────────────────────
    _, best_clf = best_model
    y_pred_best = best_clf.predict(X_test)
    class_report = classification_report(y_test, y_pred_best, output_dict=True, zero_division=0)

    # ── Confusion matrix ───────────────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred_best).tolist()

    # ── Feature importances ────────────────────────────────────────────────
    importances = {}
    if hasattr(best_clf, "feature_importances_"):
        for feat, imp in zip(feat_cols, best_clf.feature_importances_):
            importances[feat] = round(float(imp), 6)
        importances = dict(sorted(importances.items(), key=lambda x: -x[1])[:10])

    # ── Train Isolation Forest for anomaly fallback ───────────────────────
    X_normal = X_scaled[y == 0]
    iso = IsolationForest(contamination=0.1, n_estimators=100, random_state=42)
    iso.fit(X_normal)
    logger.info("Isolation Forest trained on %d normal samples", len(X_normal))

    # ── Persist ────────────────────────────────────────────────────────────
    with open(MODEL_PATH,   "wb") as f: pickle.dump(best_clf, f)
    with open(ISO_PATH,     "wb") as f: pickle.dump(iso, f)
    with open(SCALER_PATH,  "wb") as f: pickle.dump(scaler, f)
    with open(ENCODER_PATH, "wb") as f: pickle.dump(ATTACK_LABELS, f)

    metrics = {
        "trained_at":       datetime.utcnow().isoformat(),
        "best_model":       best_model[0],
        "best_cv_f1":       round(best_score, 4),
        "training_samples": len(X_train),
        "test_samples":     len(X_test),
        "num_classes":      len(ATTACK_LABELS),
        "attack_labels":    ATTACK_LABELS,
        "model_results":    results,
        "class_report":     class_report,
        "confusion_matrix": cm,
        "feature_importances": importances,
        "feature_columns":  feat_cols,
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    logger.info("Best model: %s (CV F1=%.4f) saved to %s",
                best_model[0], best_score, MODEL_PATH)
    return metrics


def load_model():
    """Load trained model, scaler, and label encoder from disk."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model not found. Run: python -m backend.detection.ml_trainer")
    with open(MODEL_PATH,   "rb") as f: clf     = pickle.load(f)
    with open(SCALER_PATH,  "rb") as f: scaler  = pickle.load(f)
    with open(ENCODER_PATH, "rb") as f: encoder = pickle.load(f)
    with open(ISO_PATH,     "rb") as f: iso     = pickle.load(f)
    return clf, scaler, encoder, iso


def predict_threat(features: dict) -> dict:
    """
    Classify a single IP behavioral feature vector.

    Parameters
    ----------
    features : dict with keys matching FEATURE_COLS

    Returns
    -------
    dict with label, label_name, confidence, risk_score, is_anomaly
    """
    clf, scaler, encoder, iso = load_model()
    feat_cols = get_feature_cols_extended()

    # Build feature vector
    row = {k: features.get(k, 0) for k in FEATURE_COLS}

    # Engineer derived features
    rc  = row["request_count"] + 1
    row["error_ratio"]        = (row["error_4xx_count"] + row["error_5xx_count"]) / rc
    row["login_fail_ratio"]   = row["failed_logins"] / (row["login_attempts"] + 1)
    row["path_density"]       = row["unique_paths"] / rc
    row["log_request_count"]  = np.log1p(row["request_count"])
    row["log_bytes_mean"]     = np.log1p(row["bytes_sent_mean"])
    row["log_time_spread"]    = np.log1p(row["time_spread_secs"])
    row["log_req_rate"]       = np.log1p(row["req_rate_per_sec"])
    row["burst_score"]        = row["req_rate_per_sec"] * row["error_ratio"]
    row["auth_attack_score"]  = row["failed_logins"] * row["req_rate_per_sec"]

    X = np.array([[row[k] for k in feat_cols]])
    X_scaled = scaler.transform(X)

    # Classification
    label    = int(clf.predict(X_scaled)[0])
    proba    = clf.predict_proba(X_scaled)[0]
    confidence = float(proba[label])

    # Isolation Forest anomaly score
    iso_score = float(iso.decision_function(X_scaled)[0])
    is_anomaly = iso.predict(X_scaled)[0] == -1
    anomaly_score = max(0, min(100, (0.5 - iso_score) * 100))

    # Risk score: blend classification confidence + anomaly score
    base_risk = {
        0: 5,   # normal
        1: 85,  # brute force
        2: 90,  # ddos
        3: 70,  # port scan
        4: 80,  # sqli
        5: 75,  # xss
        6: 95,  # privilege esc
        7: 65,  # insider threat
        8: 60,  # bot crawler
        9: 85,  # apt
    }
    risk_score = min(100, base_risk.get(label, 50) * confidence + anomaly_score * 0.3)

    severity = "HIGH" if risk_score >= 67 else "MEDIUM" if risk_score >= 34 else "LOW"

    return {
        "label":        label,
        "label_name":   encoder.get(label, "Unknown"),
        "confidence":   round(confidence, 4),
        "risk_score":   round(risk_score, 1),
        "severity":     severity,
        "is_anomaly":   bool(is_anomaly),
        "anomaly_score": round(anomaly_score, 1),
        "all_proba":    {encoder.get(i, str(i)): round(float(p), 4)
                         for i, p in enumerate(proba)},
    }


if __name__ == "__main__":
    metrics = train()
    print(f"\nTraining complete!")
    print(f"Best model:    {metrics['best_model']}")
    print(f"Best CV F1:    {metrics['best_cv_f1']}")
    print(f"Training set:  {metrics['training_samples']} samples")
    print(f"Test set:      {metrics['test_samples']} samples")
    print(f"\nTop feature importances:")
    for feat, imp in list(metrics["feature_importances"].items())[:5]:
        bar = "█" * int(imp * 200)
        print(f"  {feat:30s} {imp:.4f}  {bar}")
