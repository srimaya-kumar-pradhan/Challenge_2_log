"""
Explainable Triage Engine Module
Calculates an INVESTIGATION PRIORITY SCORE combining deterministic evidence,
temporal correlations, ML behavioral anomalies, and policy blocks.
Provides human-readable justifications for SOC analysts.
"""

import os
import pandas as pd
import numpy as np
from typing import Dict, Any, List

def calculate_investigation_priority(df: pd.DataFrame, 
                                     weights_config: Dict[str, float] = None) -> pd.DataFrame:
    """
    Compute explainable Investigation Priority Score (0.0 to 100.0).
    Categorizes endpoints into priority tiers: CRITICAL, HIGH, MEDIUM, LOW.
    Produces clear analyst justifications.
    """
    res = df.copy()

    # Default weights if not passed
    w = weights_config or {
        "malicious_quarantine": 35.0,
        "temporal_correlation": 25.0,
        "ml_anomaly_score": 15.0,
        "rare_destinations": 10.0,
        "web_block_events": 5.0,
        "usb_activity": 5.0,
        "artifact_recurrence": 5.0
    }

    scores = []
    tiers = []
    reason_lists = []

    for idx, row in res.iterrows():
        score = 0.0
        reasons = []

        # 1. Deterministic AV signature detections (up to 35 pts)
        mal_count = row.get('malicious_incident_count', 0)
        if mal_count > 0:
            subscore = min(w['malicious_quarantine'], 20.0 + (mal_count * 3.0))
            score += subscore
            reasons.append(f"Confirmed AV Signature Detection ({mal_count} unique incident(s)) [+{subscore:.1f} pts]")
            
            if row.get('has_office_lure', False):
                reasons.append("Weaponized document lure detected (.xlsx/.pdf/.docx)")
            if row.get('has_recently_used_xbel', False):
                reasons.append("Recent document execution trace (recently-used.xbel)")

        # 2. Cross-Source Temporal Correlation (up to 25 pts)
        corr_count = row.get('temporal_correlation_count', 0)
        if corr_count > 0:
            subscore = min(w['temporal_correlation'], 15.0 + (corr_count * 5.0))
            score += subscore
            reasons.append(f"Direct Temporal Web-to-Quarantine Correlation ({corr_count} incident(s) preceded by web traffic) [+{subscore:.1f} pts]")

        # 3. Behavioral Anomaly Score (up to 15 pts)
        anomaly_score = row.get('behavioral_anomaly_score', 0.0)
        if anomaly_score > 0.5:
            subscore = round(anomaly_score * w['ml_anomaly_score'], 1)
            score += subscore
            reasons.append(f"Behavioral Anomaly Score ({anomaly_score:.2f}) [+{subscore:.1f} pts]")
            if row.get('ml_anomaly_reasons') and row['ml_anomaly_reasons'] != "Fleet-typical behavior":
                reasons.append(f"Behavioral drivers: {row['ml_anomaly_reasons']}")

        # 4. Rare Web Destinations (up to 10 pts)
        rare_count = row.get('rare_destination_count', 0)
        if rare_count > 0:
            subscore = min(w['rare_destinations'], min(10.0, rare_count * 1.5))
            score += subscore
            reasons.append(f"Unusual / Rare Web Destinations ({rare_count} connections to rare hosts) [+{subscore:.1f} pts]")

        # 5. Web Policy Filter Blocks (up to 5 pts)
        block_count = row.get('web_block_count', 0)
        if block_count > 0:
            subscore = min(w['web_block_events'], min(5.0, block_count * 0.5))
            score += subscore
            reasons.append(f"Web Policy Violations / Proxy Blocks ({block_count} event(s)) [+{subscore:.1f} pts]")

        # 6. USB Telemetry (up to 5 pts)
        if row.get('has_mass_storage', False):
            subscore = w['usb_activity']
            score += subscore
            reasons.append(f"Unauthorized Mass Storage USB Attachment [+{subscore:.1f} pts]")
        elif row.get('has_usb_activity', False):
            reasons.append("Standard USB Peripheral attached (HID Mouse - non-storage)")

        # Cap score at 100.0
        final_score = min(100.0, round(score, 1))

        # Assign priority tier
        if final_score >= 70.0:
            tier = "CRITICAL"
        elif final_score >= 45.0:
            tier = "HIGH"
        elif final_score >= 20.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        scores.append(final_score)
        tiers.append(tier)
        reason_lists.append("; ".join(reasons) if reasons else "No anomalous or suspicious indicators observed")

    res['investigation_priority_score'] = scores
    res['priority_tier'] = tiers
    res['triage_justification'] = reason_lists

    # Sort descending by priority score
    res = res.sort_values('investigation_priority_score', ascending=False).reset_index(drop=True)
    return res

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    print("Triage engine module initialized.")
