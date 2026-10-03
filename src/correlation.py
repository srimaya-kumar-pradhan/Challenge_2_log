"""
Cross-Source Temporal Correlation Module
Correlates security incidents (AV quarantine, web blocks) with preceding web activity
and peripheral events within configurable time windows.
"""

import os
import pandas as pd
import numpy as np
from collections import Counter
from typing import Dict, Any, List, Tuple

def perform_temporal_correlation(dedup_incidents_df: pd.DataFrame,
                                 raw_dir: str = "Data",
                                 global_dest_counts: Counter = None,
                                 window_before_mins: int = 120,
                                 window_after_mins: int = 30,
                                 rare_threshold: int = 50) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Correlate malicious quarantine incidents with web activity logs.
    
    Returns:
        1. correlated_incidents_df: Summary per incident with correlated web context.
        2. correlated_web_events_df: Individual correlated web events for deep analyst inspection / graph linking.
    """
    # Filter for Malicious incidents
    mal_incidents = dedup_incidents_df[dedup_incidents_df['is_malicious']].copy()
    if len(mal_incidents) == 0:
        return pd.DataFrame(), pd.DataFrame()

    mal_eps = set(mal_incidents['endpoint_id'].unique())
    web_path = os.path.join(raw_dir, "web_activity.csv")

    # Load web events only for endpoints with malicious incidents (memory-efficient)
    print(f"Reading web logs for {len(mal_eps)} target endpoints...")
    ep_web_list = []
    chunk_size = 250000
    
    for chunk in pd.read_csv(web_path, chunksize=chunk_size, 
                             usecols=['endpoint_id', 'endpoint_name', 'unit', 'event_time', 'received_time', 'message']):
        chunk['ep'] = chunk['endpoint_id'].str.strip().str.upper()
        matched = chunk[chunk['ep'].isin(mal_eps)].copy()
        if len(matched) > 0:
            matched['event_dt'] = pd.to_datetime(matched['event_time'], format="%d-%m-%Y %H:%M:%S", errors='coerce')
            ep_web_list.append(matched)

    if not ep_web_list:
        return pd.DataFrame(), pd.DataFrame()

    df_mal_web = pd.concat(ep_web_list, ignore_index=True)
    df_mal_web['dest'] = df_mal_web['message'].str.strip()
    print(f"Loaded {len(df_mal_web):,} web events across target endpoints.")

    incident_summaries = []
    all_correlated_web_events = []

    for idx, inc in mal_incidents.iterrows():
        ep = inc['endpoint_id']
        inc_id = inc['incident_id']
        t_target = inc['quarantined_dt']
        
        # If quarantined_dt missing, fallback to scan_event_dt
        if pd.isna(t_target):
            t_target = inc.get('first_scan_dt', pd.NaT)
            
        if pd.isna(t_target):
            continue

        win_start = t_target - pd.Timedelta(minutes=window_before_mins)
        win_end = t_target + pd.Timedelta(minutes=window_after_mins)

        # Filter web logs for this endpoint within the temporal window
        ep_logs = df_mal_web[df_mal_web['ep'] == ep]
        in_win = ep_logs[(ep_logs['event_dt'] >= win_start) & (ep_logs['event_dt'] <= win_end)].copy()

        if len(in_win) > 0:
            in_win['incident_id'] = inc_id
            in_win['delta_to_quarantine_mins'] = (in_win['event_dt'] - t_target).dt.total_seconds() / 60.0
            
            # Destination frequencies
            dests = in_win['dest'].tolist()
            dest_counts_in_win = Counter(dests)
            
            # Rarity lookup
            rare_dests = []
            for d in dest_counts_in_win:
                g_count = global_dest_counts[d] if global_dest_counts else 999
                if g_count < rare_threshold:
                    rare_dests.append({"destination": d, "global_count": g_count, "local_count": dest_counts_in_win[d]})
                    
            rare_dests.sort(key=lambda x: x['global_count'])
            
            # Top destinations
            top_dests = dest_counts_in_win.most_common(5)
            
            all_correlated_web_events.append(in_win)
            
            incident_summaries.append({
                "incident_id": inc_id,
                "endpoint_id": ep,
                "unit": inc['unit'],
                "filename": inc['filename'],
                "sha256": inc['sha256'],
                "quarantined_at": inc['quarantined_at'],
                "quarantined_dt": t_target,
                "window_start": win_start,
                "window_end": win_end,
                "correlated_web_count": len(in_win),
                "unique_dests_in_window": len(dest_counts_in_win),
                "rare_dest_count": len(rare_dests),
                "rarest_destination": rare_dests[0]['destination'] if rare_dests else "None",
                "rarest_dest_global_count": rare_dests[0]['global_count'] if rare_dests else None,
                "top_destinations": str([d for d, c in top_dests]),
                "has_rare_destinations": (len(rare_dests) > 0)
            })

    correlated_incidents_df = pd.DataFrame(incident_summaries)
    if all_correlated_web_events:
        correlated_web_events_df = pd.concat(all_correlated_web_events, ignore_index=True)
    else:
        correlated_web_events_df = pd.DataFrame()

    return correlated_incidents_df, correlated_web_events_df

def correlate_usb_with_incidents(parsed_usb_df: pd.DataFrame, dedup_incidents_df: pd.DataFrame) -> pd.DataFrame:
    """Check if any USB device connection occurred on an endpoint with security incidents."""
    correlated_usb = []
    for idx, usb in parsed_usb_df.iterrows():
        ep = usb['endpoint_id']
        ep_incidents = dedup_incidents_df[dedup_incidents_df['endpoint_id'] == ep]
        
        correlated_usb.append({
            "endpoint_id": ep,
            "device_class": usb['device_class'],
            "vid_pid": usb['vid_pid'],
            "usb_event_time": usb['event_time'],
            "usb_event_dt": usb['event_dt'],
            "has_security_incidents": len(ep_incidents) > 0,
            "incident_count": len(ep_incidents),
            "has_malicious_incident": ep_incidents['is_malicious'].any() if len(ep_incidents) > 0 else False
        })
    return pd.DataFrame(correlated_usb)

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    from parsing import load_endpoint_security
    from quarantine import parse_quarantine_logs
    sec = load_endpoint_security()
    _, dedup_inc, _ = parse_quarantine_logs(sec)
    corr_inc, corr_web = perform_temporal_correlation(dedup_inc)
    print(f"Correlated incidents: {len(corr_inc)}")
    print(f"Unique endpoints correlated: {corr_inc['endpoint_id'].nunique()}")
    print(corr_inc[['endpoint_id', 'filename', 'quarantined_at', 'correlated_web_count', 'rare_dest_count']])
