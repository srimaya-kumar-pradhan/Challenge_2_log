"""
Exploratory Data Analysis script for baseline understanding.
Passive, read-only inspection of raw logs.
"""
import os
import pandas as pd
import numpy as np

def explore():
    data_dir = "Data"
    
    print("=== USB EVENTS ===")
    usb_df = pd.read_csv(os.path.join(data_dir, "usb_events.csv"))
    print(f"Total USB events: {len(usb_df)}")
    print(f"Unique endpoints: {usb_df['endpoint_id'].nunique()}")
    print(usb_df[['endpoint_id', 'unit', 'event_time', 'received_time', 'message']])
    
    print("\n=== ENDPOINT SECURITY ===")
    sec_df = pd.read_csv(os.path.join(data_dir, "endpoint_security.csv"))
    print(f"Total security records: {len(sec_df)}")
    print(f"Log types: {sec_df['log_type'].value_counts().to_dict()}")
    print(f"Unique endpoints: {sec_df['endpoint_id'].nunique()}")
    
    quar_mask = sec_df['log_type'] == 'quarantine'
    quar_df = sec_df[quar_mask]
    print(f"Quarantine records: {len(quar_df)}")
    
    # Check messages in quarantine
    mal_quar = quar_df[quar_df['message'].str.contains("FileType: Malicious", case=False, na=False)]
    print(f"Malicious quarantine records: {len(mal_quar)}")
    print(f"Unique endpoints with Malicious quarantine: {mal_quar['endpoint_id'].nunique()}")
    
    no_mal = quar_df[quar_df['message'].str.contains("No Malicious files found", case=False, na=False)]
    print(f"'No Malicious files found' records: {len(no_mal)}")
    no_susp = quar_df[quar_df['message'].str.contains("No suspicious file found", case=False, na=False)]
    print(f"'No suspicious file found' records: {len(no_susp)}")
    
    # Other quarantine records
    other_quar = quar_df[~quar_df['message'].str.contains("No Malicious|No suspicious|FileType: Malicious", case=False, na=False)]
    print(f"Other quarantine records: {len(other_quar)}")
    if len(other_quar) > 0:
        print("Sample other quarantine messages:")
        for m in other_quar['message'].head(10):
            print("  ", m[:100])
            
    # Check av_scan and web_block
    for lt in ['av_scan', 'web_block']:
        sub = sec_df[sec_df['log_type'] == lt]
        print(f"\n=== Log Type: {lt} (count={len(sub)}, endpoints={sub['endpoint_id'].nunique()}) ===")
        print("Sample messages:")
        for m in sub['message'].head(5):
            print("  ", m[:120])
        matches = sub[sub['message'].str.contains('infected|block|alert|threat|found|quarantine|malicious', case=False, na=False)]
        print(f"Keyword matches in {lt}: {len(matches)}")
        if len(matches) > 0:
            for m in matches['message'].head(5):
                print("  * ", m[:120])

    # Quarantine file analysis
    print("\n=== DETAILED QUARANTINE FILE ANALYSIS ===")
    file_quar = quar_df[quar_df['message'].str.startswith("File:")]
    print(f"Total 'File:' quarantine rows: {len(file_quar)}")
    
    # Parse File, Quarantined At, FileType, SHA256
    parsed_files = []
    for idx, row in file_quar.iterrows():
        msg = row['message']
        parts = [p.strip() for p in msg.split('|')]
        item = {
            'endpoint_id': row['endpoint_id'],
            'unit': row['unit'],
            'event_time': row['event_time'],
            'received_time': row['received_time'],
            'raw_message': msg
        }
        for p in parts:
            if p.startswith('File:'):
                item['filename'] = p.replace('File:', '').strip()
            elif p.startswith('Quarantined At:'):
                item['quarantined_at'] = p.replace('Quarantined At:', '').strip()
            elif p.startswith('FileType:'):
                item['file_type'] = p.replace('FileType:', '').strip()
            elif p.startswith('SHA256:'):
                item['sha256'] = p.replace('SHA256:', '').strip()
        parsed_files.append(item)
    
    pq_df = pd.DataFrame(parsed_files)
    print(f"Parsed quarantine rows: {len(pq_df)}")
    print(f"Unique files: {pq_df['filename'].nunique()}")
    print(f"Unique SHA256 hashes: {pq_df['sha256'].nunique()}")
    print(f"FileType counts:\n{pq_df['file_type'].value_counts()}")
    print("\nTop filenames quarantined:")
    print(pq_df['filename'].value_counts().head(15))
    
    # Check deduplication impact:
    # A scan re-lists the quarantine folder! So (endpoint_id, filename, quarantined_at, sha256) is repeated across scan dates!
    dedup_events = pq_df.drop_duplicates(subset=['endpoint_id', 'filename', 'quarantined_at', 'sha256'])
    print(f"\nUnique quarantine incidents (deduplicated by endpoint, file, quarantined_at, sha256): {len(dedup_events)}")
    print(f"Unique endpoints with deduplicated incidents: {dedup_events['endpoint_id'].nunique()}")
    
    dedup_mal = dedup_events[dedup_events['file_type'] == 'Malicious']
    print(f"Unique Malicious incidents: {len(dedup_mal)}")
    print(f"Endpoints with unique Malicious incidents: {dedup_mal['endpoint_id'].nunique()}")
    print("\nSample unique Malicious incidents:")
    print(dedup_mal[['endpoint_id', 'filename', 'quarantined_at', 'sha256']].head(15))

if __name__ == "__main__":
    explore()

