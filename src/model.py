from __future__ import annotations
import logging
from dataclasses import dataclass
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from src.features import FEATURE_COLUMNS

logger = logging.getLogger(__name__)

@dataclass
class ModelArtifact:
    scaler: StandardScaler
    model: IsolationForest
    feature_columns: list
    training_size: int
    contamination: float

class AnomalyDetector:
    def __init__(self, contamination=0.01, n_estimators=100, random_state=42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.artifact = None

    def fit(self, df):
        X = self._extract_matrix(df)
        if len(X) < 20:
            raise ValueError(f"Need at least 20 windows to train, got {len(X)}.")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        model.fit(X_scaled)
        self.artifact = ModelArtifact(
            scaler=scaler, model=model,
            feature_columns=FEATURE_COLUMNS,
            training_size=len(X),
            contamination=self.contamination,
        )
        logger.info("Trained on %d windows", len(X))
        return self.artifact

    def score(self, df):
        if self.artifact is None:
            raise RuntimeError("Model not loaded. Call fit() or load() first.")
        X = self._extract_matrix(df)
        X_scaled = self.artifact.scaler.transform(X)
        return self.artifact.model.decision_function(X_scaled)

    def predict_anomaly(self, df, threshold=0.0):
        scores = self.score(df)
        df = df.copy()
        df["anomaly_score"] = scores
        df["is_anomaly"] = scores < threshold
        return df

    def save(self, path):
        if self.artifact is None:
            raise RuntimeError("Nothing to save.")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.artifact, path)
        logger.info("Saved model to %s", path)

    def load(self, path):
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        self.artifact = joblib.load(path)
        logger.info("Loaded model from %s", path)
        return self.artifact

    @staticmethod
    def _extract_matrix(df):
        missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if missing:
            raise ValueError(f"Missing columns: {missing}")
        return df[FEATURE_COLUMNS].to_numpy(dtype=float)

def severity_from_score(score):
    if score < -0.30: return "CRITICAL"
    if score < -0.20: return "HIGH"
    if score < -0.10: return "MEDIUM"
    return "LOW"
