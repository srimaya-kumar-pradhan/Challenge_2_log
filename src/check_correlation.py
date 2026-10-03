"""
Analyze temporal correlation between Malicious Quarantine incidents and Web Activity.
"""
import os
import pandas as pd
from collections import Counter

def correlate():
    # 1. Load quarantine incidents
    sec = pd.read_csv("Data/endpoint_security.csv")
    file_quar = sec[sec['message'].str.startswith("File:")].copy()
    
    incidents = []
    for idx, row in file_quar.iterrows():
        parts = [p.strip() for p in row['message'].split('|')]
        fn, qa, ft, sha = "", "", "", ""
        for p in parts:
            if p.startswith('File:'): fn = p.replace('File:', '').strip()
            elif p.startswith('Quarantined At:'): qa = p.replace('Quarantined At:', '').strip()
            elif p.startswith('FileType:'): ft = p.replace('FileType:', '').strip()
            elif p.startswith('SHA256:'): sha = p.replace('SHA256:', '').strip()
            
        if ft == 'Malicious':
            incidents.append({
                'endpoint_id': row['endpoint_id'],
                'unit': row['unit'],
                'scan_event_time': row['event_time'],
                'quarantined_at': qa,
                'filename': fn,
                'sha256': sha
            })
            
    df_inc = pd.DataFrame(incidents)
    # Deduplicate incidents by endpoint, file, quarantined_at, sha256
    dedup_inc = df_inc.drop_duplicates(subset=['endpoint_id', 'filename', 'quarantined_at', 'sha256']).copy()
    print(f"Total unique malicious incidents: {len(dedup_inc)} across {dedup_inc['endpoint_id'].nunique()} endpoints")
    
    # Convert quarantined_at to datetime (format is 'YYYY-MM-DD HH:MM')
    dedup_inc['qa_dt'] = pd.to_datetime(dedup_inc['quarantined_at'], format='%Y-%m-%d %H:%M', errors='coerce')
    # Also parse first scan_event_time (format 'DD-MM-YYYY HH:MM:SS')
    dedup_inc['scan_dt'] = pd.to_datetime(dedup_inc['scan_event_time'], format='%d-%m-%Y %H:%M:%S', errors='coerce')
    
    # We want to see web activity around qa_dt (or scan_dt if qa_dt is before web logs start)
    # Note: Web logs are 10-09-2026 to 21-09-2026.
    print(f"Incidents with qa_dt between 2026-09-10 and 2026-09-22:")
    in_range = dedup_inc[(dedup_inc['qa_dt'] >= '2026-09-10') & (dedup_inc['qa_dt'] <= '2026-09-22')]
    print(f"Count: {len(in_range)} across {in_range['endpoint_id'].nunique()} endpoints")
    print(in_range[['endpoint_id', 'filename', 'quarantined_at', 'qa_dt']])
    
    # Let's inspect all 33 endpoints and check their date ranges in web activity
    mal_eps = set(dedup_inc['endpoint_id'].unique())
    
    print("\nReading web activity for the 33 malicious endpoints...")
    web_chunks = pd.read_csv("Data/web_activity.csv", chunksize=250000, usecols=['endpoint_id', 'event_time', 'message'])
    ep_web_list = []
    global_dest_counts = Counter()
    
    for chunk in web_chunks:
        global_dest_counts.update(chunk['message'].dropna())
        m = chunk[chunk['endpoint_id'].isin(mal_eps)]
        if len(m) > 0:
            ep_web_list.append(m)
            
    df_ep_web = pd.concat(ep_web_list)
    df_ep_web['web_dt'] = pd.to_datetime(df_ep_web['event_time'], format='%d-%m-%Y %H:%M:%S', errors='coerce')
    print(f"Total web rows for 33 malicious endpoints: {len(df_ep_web)}")
    print(f"Endpoints of the 33 present in web activity: {df_ep_web['endpoint_id'].nunique()}/33")
    
    # Check temporal correlation window (e.g. 1 hour before quarantine, 2 hours before quarantine)
    # Check for both qa_dt and scan_dt
    correlation_results = []
    for idx, inc in dedup_inc.iterrows():
        ep = inc['endpoint_id']
        ep_web = df_ep_web[df_ep_web['endpoint_id'] == ep]
        if len(ep_web) == 0:
            continue
            
        t_target = inc['qa_dt']
        if pd.isna(t_target):
            t_target = inc['scan_dt']
            
        # Check window: 2 hours before to 30 mins after
        win_start = t_target - pd.Timedelta(hours=2)
        win_end = t_target + pd.Timedelta(minutes=30)
        
        correlated_web = ep_web[(ep_web['web_dt'] >= win_start) & (ep_web['web_dt'] <= win_end)]
        if len(correlated_web) > 0:
            # Check destination frequency (rarity)
            dests = correlated_web['message'].tolist()
            dest_freqs = [(d, global_dest_counts[d]) for d in set(dests)]
            dest_freqs.sort(key=lambda x: x[1])
            rarest = [d for d, c in dest_freqs if c < 50]
            
            correlation_results.append({
                'endpoint_id': ep,
                'filename': inc['filename'],
                'quarantined_at': inc['quarantined_at'],
                't_target': str(t_target),
                'web_count_in_window': len(correlated_web),
                'unique_dests_in_window': len(set(dests)),
                'rare_dest_count': len(rarest),
                'top_rare_dests': dest_freqs[:5]
            })
            
    df_corr = pd.DataFrame(correlation_results)
    print(f"\nCorrelated incidents found: {len(df_corr)} across {df_corr['endpoint_id'].nunique() if len(df_corr) > 0 else 0} endpoints")
    if len(df_corr) > 0:
        for idx, r in df_corr.iterrows():
            print(f"Endpoint: {r['endpoint_id']} | File: {r['filename']} | Time: {r['quarantined_at']} | Web rows: {r['web_count_in_window']} | Rare dests: {r['rare_dest_count']}")
            print(f"   Rare destinations: {r['top_rare_dests']}")

if __name__ == "__main__":
    correlate()
