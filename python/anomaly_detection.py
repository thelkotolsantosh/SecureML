"""
Network Traffic Anomaly Detection using Isolation Forest
=========================================================
A data science approach to cybersecurity — detects anomalous
network traffic patterns that may indicate intrusions or attacks.
"""

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns

# ── Logging Setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


# ── Data Generation ────────────────────────────────────────────────────────────
def generate_sample_traffic(n_normal: int = 1000, n_anomalies: int = 50, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic network traffic data.

    Features:
        - packet_size     : bytes per packet
        - duration        : session duration (seconds)
        - bytes_sent      : total bytes sent
        - bytes_received  : total bytes received
        - num_connections : number of connections in session
        - port            : destination port number
    """
    rng = np.random.default_rng(seed)

    # Normal traffic
    normal = pd.DataFrame({
        "packet_size":     rng.normal(512,   150,  n_normal).clip(64, 1500),
        "duration":        rng.normal(30,    10,   n_normal).clip(1, 120),
        "bytes_sent":      rng.normal(5000,  1500, n_normal).clip(100, 20000),
        "bytes_received":  rng.normal(8000,  2000, n_normal).clip(100, 30000),
        "num_connections": rng.integers(1, 20, n_normal),
        "port":            rng.choice([80, 443, 22, 8080, 3306], n_normal),
        "label":           0,
    })

    # Anomalous traffic (DoS / data exfil / port scans)
    anomalies = pd.DataFrame({
        "packet_size":     rng.choice(
            [rng.normal(64, 5, n_anomalies), rng.normal(1490, 5, n_anomalies)],
            axis=0,
        ).clip(64, 1500),
        "duration":        rng.normal(0.5,  0.2,  n_anomalies).clip(0.01, 2),
        "bytes_sent":      rng.normal(50000, 5000, n_anomalies).clip(30000, 100000),
        "bytes_received":  rng.normal(100,   50,   n_anomalies).clip(10, 500),
        "num_connections": rng.integers(200, 1000, n_anomalies),
        "port":            rng.integers(1024, 65535, n_anomalies),
        "label":           1,
    })

    df = pd.concat([normal, anomalies], ignore_index=True).sample(frac=1, random_state=seed)
    log.info("Generated %d normal + %d anomalous traffic records.", n_normal, n_anomalies)
    return df


# ── Model ──────────────────────────────────────────────────────────────────────
class AnomalyDetector:
    """Wraps Isolation Forest with scaling and reporting helpers."""

    FEATURES = ["packet_size", "duration", "bytes_sent", "bytes_received", "num_connections", "port"]

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, random_state: int = 42):
        self.scaler = StandardScaler()
        self.model  = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )

    def fit(self, df: pd.DataFrame) -> "AnomalyDetector":
        X = df[self.FEATURES]
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        log.info("Model trained on %d samples.", len(df))
        return self

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        """Returns 1 for anomaly, 0 for normal."""
        X_scaled = self.scaler.transform(df[self.FEATURES])
        raw = self.model.predict(X_scaled)          # sklearn: -1 anomaly, 1 normal
        return np.where(raw == -1, 1, 0)

    def anomaly_scores(self, df: pd.DataFrame) -> np.ndarray:
        X_scaled = self.scaler.transform(df[self.FEATURES])
        return -self.model.score_samples(X_scaled)  # higher = more anomalous


# ── Visualisation ──────────────────────────────────────────────────────────────
def plot_results(df: pd.DataFrame, predictions: np.ndarray, scores: np.ndarray, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    palette = {0: "#2196F3", 1: "#F44336"}

    # 1. Scatter: bytes_sent vs num_connections coloured by prediction
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Network Traffic Anomaly Detection", fontsize=14, fontweight="bold")

    for ax, col, title in zip(
        axes,
        [predictions, df["label"].values],
        ["Predicted Labels", "True Labels"],
    ):
        colours = [palette[int(c)] for c in col]
        ax.scatter(df["bytes_sent"], df["num_connections"], c=colours, alpha=0.5, s=20, edgecolors="none")
        ax.set_xlabel("Bytes Sent")
        ax.set_ylabel("Num Connections")
        ax.set_title(title)
        patches = [
            mpatches.Patch(color=palette[0], label="Normal"),
            mpatches.Patch(color=palette[1], label="Anomaly"),
        ]
        ax.legend(handles=patches)

    plt.tight_layout()
    scatter_path = out_dir / "scatter_anomaly.png"
    fig.savefig(scatter_path, dpi=150)
    plt.close(fig)
    log.info("Scatter plot saved → %s", scatter_path)

    # 2. Anomaly score distribution
    fig, ax = plt.subplots(figsize=(8, 4))
    for label, colour, name in [(0, "#2196F3", "Normal"), (1, "#F44336", "Anomaly")]:
        mask = df["label"].values == label
        ax.hist(scores[mask], bins=40, alpha=0.6, color=colour, label=name, density=True)
    ax.set_xlabel("Anomaly Score (higher = more anomalous)")
    ax.set_ylabel("Density")
    ax.set_title("Anomaly Score Distribution")
    ax.legend()
    score_path = out_dir / "score_distribution.png"
    fig.savefig(score_path, dpi=150)
    plt.close(fig)
    log.info("Score distribution plot saved → %s", score_path)

    # 3. Confusion matrix
    cm = confusion_matrix(df["label"], predictions)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Normal", "Anomaly"],
                yticklabels=["Normal", "Anomaly"], ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix")
    cm_path = out_dir / "confusion_matrix.png"
    fig.savefig(cm_path, dpi=150)
    plt.close(fig)
    log.info("Confusion matrix saved → %s", cm_path)


# ── CLI ────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Network Traffic Anomaly Detector")
    p.add_argument("--input",         type=Path, default=None,   help="CSV file with traffic data (optional)")
    p.add_argument("--output-dir",    type=Path, default=Path("output"), help="Directory for plots")
    p.add_argument("--contamination", type=float, default=0.05,  help="Expected anomaly fraction (default 0.05)")
    p.add_argument("--n-estimators",  type=int,   default=100,   help="Number of trees in IsolationForest")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Load or generate data
    if args.input and args.input.exists():
        df = pd.read_csv(args.input)
        log.info("Loaded %d records from %s", len(df), args.input)
    else:
        log.info("No input file provided — generating synthetic data.")
        df = generate_sample_traffic()
        sample_path = Path("python/data/sample_traffic.csv")
        sample_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(sample_path, index=False)
        log.info("Sample data saved → %s", sample_path)

    # Train & predict
    detector = AnomalyDetector(
        contamination=args.contamination,
        n_estimators=args.n_estimators,
    )
    detector.fit(df)
    predictions = detector.predict(df)
    scores      = detector.anomaly_scores(df)

    # Evaluation
    n_detected = predictions.sum()
    log.info("Detected %d anomalies out of %d records (%.1f%%).",
             n_detected, len(df), 100 * n_detected / len(df))

    if "label" in df.columns:
        print("\n── Classification Report ──────────────────────────────")
        print(classification_report(df["label"], predictions,
                                    target_names=["Normal", "Anomaly"]))

    # Visualise
    plot_results(df, predictions, scores, args.output_dir)
    log.info("Done. Results in → %s/", args.output_dir)


if __name__ == "__main__":
    main()
