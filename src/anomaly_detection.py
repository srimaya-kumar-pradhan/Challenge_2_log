"""
Unsupervised Anomaly Detection Module using Isolation Forest
Identifies behaviorally unusual endpoints across fleet activity.
Output represents a BEHAVIORAL ANOMALY SCORE, NOT probability of compromise.
"""

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from typing import Dict, Any, List, Tuple

def train_isolation_forest(feature_df: pd.DataFrame,
                           feature_cols: List[str],
                           contamination: float = 0.10,
                           random_state: int = 42) -> Tuple[pd.DataFrame, IsolationForest, RobustScaler]:
    """
    Fits an Isolation Forest model to score behavioral anomalies across endpoints.
    
    Why RobustScaler:
    Outlier counts (such as web events in tens of thousands) would heavily skew Standard Scaler.
    RobustScaler uses median and IQR, preventing extreme values from distorting scaling.
    
    Why Isolation Forest:
    1. Unsupervised: No ground-truth compromise labels exist in raw SOC telemetry.
    2. Isolates anomalies instead of modeling normal density: anomalous points require fewer splits to isolate.
    3. Computationally efficient: Tree-based ensemble scales linearly with data.
    4. Interpretability: Isolation depth directly maps to behavioral distinctiveness.
    """
    df = feature_df.copy()
    
    # Verify selected feature columns exist
    valid_cols = [c for c in feature_cols if c in df.columns]
    X_raw = df[valid_cols].astype(float).values

    # Scale features
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X_raw)

    # Initialize Isolation Forest
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    
    # Fit and score
    iso_forest.fit(X_scaled)
    
    # Raw decision function: higher means normal, lower means anomalous
    raw_scores = iso_forest.decision_function(X_scaled)
    # Predict: -1 for anomaly, 1 for normal
    predictions = iso_forest.predict(X_scaled)

    # Normalize anomaly score to [0.0, 1.0] where 1.0 is most anomalous
    # raw_scores typically range from ~ -0.3 to +0.3
    min_s = raw_scores.min()
    max_s = raw_scores.max()
    if max_s > min_s:
        normalized_scores = 1.0 - ((raw_scores - min_s) / (max_s - min_s))
    else:
        normalized_scores = np.zeros_like(raw_scores)

    df['raw_decision_score'] = np.round(raw_scores, 4)
    df['behavioral_anomaly_score'] = np.round(normalized_scores, 4)
    df['is_behavioral_anomaly'] = (predictions == -1)

    # Calculate feature anomaly attribution (which features deviated most from median)
    medians = np.median(X_raw, axis=0)
    iqr = np.percentile(X_raw, 75, axis=0) - np.percentile(X_raw, 25, axis=0)
    iqr[iqr == 0] = 1.0 # prevent div zero

    attributions = []
    for row_idx, row_vals in enumerate(X_raw):
        deviations = (row_vals - medians) / iqr
        # Top 3 features with highest positive deviation from fleet median
        top_indices = np.argsort(deviations)[::-1][:3]
        reasons = [f"{valid_cols[i]} (+{deviations[i]:.1f}x IQR)" for i in top_indices if deviations[i] > 1.0]
        attributions.append("; ".join(reasons) if reasons else "Fleet-typical behavior")

    df['ml_anomaly_reasons'] = attributions

    return df, iso_forest, scaler

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    print("Isolation Forest module initialized.")
