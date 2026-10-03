"""
Web Activity and Policy Filter Analysis Module
Processes 2.8M web activity events, measures destination frequency distribution,
calculates behavioral metrics (entropy, rarity ratio), and correlates web policy blocks.
"""

import os
import math
import pandas as pd
import numpy as np
from collections import Counter
from typing import Dict, Any, Tuple, List
import yaml

def calculate_shannon_entropy(counts: List[int]) -> float:
    """Calculate Shannon entropy for destination frequency distribution."""
    total = sum(counts)
    if total <= 1:
        return 0.0
    entropy = 0.0
    for c in counts:
        p = c / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def analyze_web_activity(raw_dir: str = "Data", 
                         chunk_size: int = 250000, 
                         rare_threshold: int = 50) -> Tuple[pd.DataFrame, pd.DataFrame, Counter]:
    """
    Pass 1 & 2 over web_activity.csv to produce:
    1. ep_web_summary_df: Endpoint-level web behavior features.
    2. rare_destinations_df: Table of all rare destinations with global count.
    3. global_dest_counts: Full Counter of global destinations.
    """
    web_path = os.path.join(raw_dir, "web_activity.csv")
    
    # Pass 1: Global destination frequencies and endpoint event counts
    print("Pass 1: Computing global destination frequencies...")
    global_dest_counts = Counter()
    ep_event_counts = Counter()
    
    chunk_idx = 0
    for chunk in pd.read_csv(web_path, chunksize=chunk_size, usecols=['endpoint_id', 'message']):
        chunk_idx += 1
        global_dest_counts.update(chunk['message'].dropna().str.strip())
        ep_event_counts.update(chunk['endpoint_id'].dropna().str.strip().str.upper())
        if chunk_idx % 4 == 0:
            print(f"  Processed {chunk_idx * chunk_size:,} rows in Pass 1...")

    print(f"Pass 1 complete. Total unique destinations: {len(global_dest_counts):,}")

    # Set of rare destinations
    rare_dest_set = {dest for dest, count in global_dest_counts.items() if count < rare_threshold}
    print(f"Identified {len(rare_dest_set):,} rare destinations (global count < {rare_threshold})")

    # Pass 2: Per-endpoint detailed statistics
    print("Pass 2: Extracting per-endpoint web features...")
    ep_dest_freqs: Dict[str, Counter] = {}
    ep_rare_counts = Counter()
    ep_time_ranges: Dict[str, Dict[str, Any]] = {}
    
    chunk_idx = 0
    for chunk in pd.read_csv(web_path, chunksize=chunk_size, usecols=['endpoint_id', 'event_time', 'message']):
        chunk_idx += 1
        chunk['event_dt'] = pd.to_datetime(chunk['event_time'], format="%d-%m-%Y %H:%M:%S", errors='coerce')
        chunk['ep'] = chunk['endpoint_id'].str.strip().str.upper()
        chunk['msg'] = chunk['message'].str.strip()
        
        for ep, ep_group in chunk.groupby('ep'):
            if ep not in ep_dest_freqs:
                ep_dest_freqs[ep] = Counter()
                ep_time_ranges[ep] = {
                    'min_dt': ep_group['event_dt'].min(),
                    'max_dt': ep_group['event_dt'].max(),
                    'dates': set(ep_group['event_dt'].dt.date.dropna())
                }
            else:
                ep_time_ranges[ep]['min_dt'] = min(ep_time_ranges[ep]['min_dt'], ep_group['event_dt'].min())
                ep_time_ranges[ep]['max_dt'] = max(ep_time_ranges[ep]['max_dt'], ep_group['event_dt'].max())
                ep_time_ranges[ep]['dates'].update(ep_group['event_dt'].dt.date.dropna())

            msgs = ep_group['msg'].dropna()
            ep_dest_freqs[ep].update(msgs)
            
            # Count rare
            rare_in_group = msgs[msgs.isin(rare_dest_set)]
            if len(rare_in_group) > 0:
                ep_rare_counts[ep] += len(rare_in_group)
                
        if chunk_idx % 4 == 0:
            print(f"  Processed {chunk_idx * chunk_size:,} rows in Pass 2...")

    # Build endpoint feature summary
    summary_rows = []
    for ep, total_events in ep_event_counts.items():
        dest_counts = ep_dest_freqs.get(ep, Counter())
        counts_list = list(dest_counts.values())
        unique_dests = len(dest_counts)
        entropy = calculate_shannon_entropy(counts_list)
        rare_cnt = ep_rare_counts.get(ep, 0)
        rare_ratio = (rare_cnt / total_events) if total_events > 0 else 0.0
        
        time_info = ep_time_ranges.get(ep, {'min_dt': pd.NaT, 'max_dt': pd.NaT, 'dates': set()})
        active_days = len(time_info['dates'])
        
        summary_rows.append({
            "endpoint_id": ep,
            "total_web_events": total_events,
            "unique_destinations": unique_dests,
            "destination_diversity_ratio": round(unique_dests / total_events, 4) if total_events > 0 else 0.0,
            "destination_entropy": entropy,
            "rare_destination_count": rare_cnt,
            "rare_destination_ratio": round(rare_ratio, 6),
            "active_web_days": active_days,
            "first_web_event_dt": time_info['min_dt'],
            "last_web_event_dt": time_info['max_dt']
        })

    ep_web_summary_df = pd.DataFrame(summary_rows)

    # Rare destinations table
    rare_dest_rows = [
        {"destination": dest, "global_count": count, "is_singleton": (count == 1)}
        for dest, count in global_dest_counts.items() if count < rare_threshold
    ]
    rare_destinations_df = pd.DataFrame(rare_dest_rows).sort_values("global_count", ascending=True)

    return ep_web_summary_df, rare_destinations_df, global_dest_counts

def analyze_web_blocks(sec_df: pd.DataFrame) -> pd.DataFrame:
    """Analyze web filter block events from endpoint security."""
    wb_mask = sec_df['log_type'] == 'web_block'
    wb_df = sec_df[wb_mask].copy()
    
    ep_blocks = wb_df.groupby('endpoint_id').agg(
        web_block_count=('message', 'count'),
        unique_blocked_domains=('message', 'nunique')
    ).reset_index()
    return ep_blocks

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    print("Testing web analysis module...")
    ep_summary, rare_df, _ = analyze_web_activity(chunk_size=500000, rare_threshold=50)
    print(f"Endpoints profiled: {len(ep_summary)}")
    print(ep_summary.head())
