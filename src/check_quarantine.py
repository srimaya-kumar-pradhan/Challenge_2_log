"""
Examine quarantine timestamps, quarantined_at, event_time, and check web activity around those times.
"""
import os
import pandas as pd

def check_quarantine_timing():
    sec_df = pd.read_csv("Data/endpoint_security.csv")
    quar_files = sec_df[sec_df['message'].str.startswith("File:")].copy()
    
    parsed = []
    for idx, row in quar_files.iterrows():
        parts = [p.strip() for p in row['message'].split('|')]
        fn, qa, ft, sha = "", "", "", ""
        for p in parts:
            if p.startswith('File:'): fn = p.replace('File:', '').strip()
            elif p.startswith('Quarantined At:'): qa = p.replace('Quarantined At:', '').strip()
            elif p.startswith('FileType:'): ft = p.replace('FileType:', '').strip()
            elif p.startswith('SHA256:'): sha = p.replace('SHA256:', '').strip()
        parsed.append({
            'endpoint_id': row['endpoint_id'],
            'unit': row['unit'],
            'event_time': row['event_time'],
            'received_time': row['received_time'],
            'filename': fn,
            'quarantined_at': qa,
            'file_type': ft,
            'sha256': sha
        })
    df = pd.DataFrame(parsed)
    
    # Filter for Malicious
    mal = df[df['file_type'] == 'Malicious']
    print(f"Total Malicious quarantine records: {len(mal)}")
    dedup_mal = mal.drop_duplicates(subset=['endpoint_id', 'filename', 'quarantined_at', 'sha256'])
    print(f"Deduplicated Malicious incidents: {len(dedup_mal)}")
    
    print("\nEndpoints with Malicious incidents:")
    ep_counts = dedup_mal['endpoint_id'].value_counts()
    print(ep_counts)
    
    # Check EPJ76RZV specifically
    print("\n=== EPJ76RZV Quarantine Details ===")
    ep_sample = df[df['endpoint_id'] == 'EPJ76RZV']
    print(ep_sample[['event_time', 'filename', 'quarantined_at', 'file_type', 'sha256']])
    
    # Check date range of quarantined_at vs event_time
    print("\nQuarantined At sample values:")
    print(df['quarantined_at'].value_counts().head(10))

if __name__ == "__main__":
    check_quarantine_timing()
