"""
Feature Engineering Module
Constructs an explainable, tabular endpoint-level feature matrix
combining web activity, AV quarantine telemetry, web policy filters, and USB logs.
"""

import os
import pandas as pd
import numpy as np
from typing import Dict, Any, List

def build_endpoint_feature_matrix(all_endpoints: List[str],
                                  ep_quar_summary: pd.DataFrame,
                                  ep_web_summary: pd.DataFrame,
                                  ep_web_blocks: pd.DataFrame,
                                  ep_usb_summary: pd.DataFrame,
                                  corr_incidents: pd.DataFrame) -> pd.DataFrame:
    """
    Consolidate all per-endpoint domain metrics into an interpretable feature matrix.
    Ensures full fleet representation (all 248 endpoints) with 0-imputation for absent telemetry.
    """
    base_df = pd.DataFrame({"endpoint_id": sorted(list(set(all_endpoints)))})

    # Merge quarantine features
    if ep_quar_summary is not None and not ep_quar_summary.empty:
        base_df = base_df.merge(ep_quar_summary, on="endpoint_id", how="left")
    
    # Merge web summary features
    if ep_web_summary is not None and not ep_web_summary.empty:
        base_df = base_df.merge(ep_web_summary, on="endpoint_id", how="left")

    # Merge web block features
    if ep_web_blocks is not None and not ep_web_blocks.empty:
        base_df = base_df.merge(ep_web_blocks, on="endpoint_id", how="left")

    # Merge USB summary features
    if ep_usb_summary is not None and not ep_usb_summary.empty:
        base_df = base_df.merge(ep_usb_summary, on="endpoint_id", how="left")

    # Temporal correlation counts per endpoint
    if corr_incidents is not None and not corr_incidents.empty:
        corr_counts = corr_incidents.groupby("endpoint_id").size().reset_index(name="temporal_correlation_count")
        base_df = base_df.merge(corr_counts, on="endpoint_id", how="left")
    else:
        base_df["temporal_correlation_count"] = 0

    # Impute missing numeric values with 0
    numeric_cols = [
        "total_quarantine_incidents", "malicious_incident_count", "unique_malicious_hashes",
        "unique_malicious_files", "distinct_artifact_types", "total_web_events",
        "unique_destinations", "destination_diversity_ratio", "destination_entropy",
        "rare_destination_count", "rare_destination_ratio", "active_web_days",
        "web_block_count", "unique_blocked_domains", "usb_event_count",
        "mass_storage_event_count", "temporal_correlation_count"
    ]
    for col in numeric_cols:
        if col in base_df.columns:
            base_df[col] = base_df[col].fillna(0)
        else:
            base_df[col] = 0

    # Boolean columns
    bool_cols = ["has_recently_used_xbel", "has_office_lure", "has_usb_activity", "has_mass_storage"]
    for col in bool_cols:
        if col in base_df.columns:
            base_df[col] = base_df[col].fillna(False).astype(bool)
        else:
            base_df[col] = False

    return base_df

def get_feature_documentation() -> List[Dict[str, str]]:
    """Return explicit documentation and rationale for all engineering features."""
    return [
        {
            "feature": "malicious_quarantine_count",
            "type": "Integer (Count)",
            "rationale": "Direct AV signature match. Number of unique malware incidents quarantined on this host.",
            "source": "endpoint_security.csv (quarantine)"
        },
        {
            "feature": "unique_malicious_hashes",
            "type": "Integer (Count)",
            "rationale": "Diversity of malware families / payloads detected on the host.",
            "source": "endpoint_security.csv (SHA256)"
        },
        {
            "feature": "temporal_correlation_count",
            "type": "Integer (Count)",
            "rationale": "Incidents where external web activity directly preceded AV quarantine within a 2-hour window.",
            "source": "web_activity.csv + endpoint_security.csv"
        },
        {
            "feature": "rare_destination_count",
            "type": "Integer (Count)",
            "rationale": "Connections to destinations seen < 50 times across all 2.8M events in the fleet.",
            "source": "web_activity.csv"
        },
        {
            "feature": "rare_destination_ratio",
            "type": "Float (Ratio)",
            "rationale": "Proportion of total web traffic targeted at fleet-rare destinations.",
            "source": "web_activity.csv"
        },
        {
            "feature": "destination_entropy",
            "type": "Float (Shannon)",
            "rationale": "Information entropy of destination distribution. High entropy indicates diverse surfing; low indicates concentrated activity.",
            "source": "web_activity.csv"
        },
        {
            "feature": "web_block_count",
            "type": "Integer (Count)",
            "rationale": "Policy violation indicators from perimeter / web-filtering proxies.",
            "source": "endpoint_security.csv (web_block)"
        },
        {
            "feature": "has_recently_used_xbel",
            "type": "Boolean",
            "rationale": "Indicates execution/opening of tracked files registered in GNOME/GTK desktop recent history.",
            "source": "endpoint_security.csv (quarantine)"
        },
        {
            "feature": "has_office_lure",
            "type": "Boolean",
            "rationale": "Indicates presence of weaponized document lures (.docx, .xlsx, .pdf) commonly used in initial access.",
            "source": "endpoint_security.csv (quarantine)"
        },
        {
            "feature": "usb_event_count",
            "type": "Integer (Count)",
            "rationale": "Volume of USB peripheral attachment events.",
            "source": "usb_events.csv"
        },
        {
            "feature": "has_mass_storage",
            "type": "Boolean",
            "rationale": "Detection of unauthorized mass storage / flash memory attachment.",
            "source": "usb_events.csv"
        }
    ]

if __name__ == "__main__":
    docs = get_feature_documentation()
    print(f"Total documented features: {len(docs)}")
    for d in docs:
        print(f"- {d['feature']:30s} | {d['type']:18s} | {d['rationale']}")
