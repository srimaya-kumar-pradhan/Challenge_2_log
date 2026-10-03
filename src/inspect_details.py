"""
Detailed inspection script for AV, web_block, time ranges, and web activity sampling.
"""
import os
import pandas as pd
from collections import Counter

data_dir = "Data"

def inspect_details():
    sec_df = pd.read_csv(os.path.join(data_dir, "endpoint_security.csv"))
    av_df = sec_df[sec_df['log_type'] == 'av_scan']
    print(f"Total av_scan messages: {len(av_df)}")
    print(f"Unique av_scan messages: {av_df['message'].nunique()}")
    print("Top av_scan messages:")
    print(av_df['message'].value_counts().head(10))
    
    diff_av = av_df[~av_df['message'].str.contains('System Scan Completed', case=False, na=False)]
    print(f"\nNon-System Scan Completed AV messages: {len(diff_av)}")
    if len(diff_av) > 0:
        for m in diff_av['message'].head(20):
            print("  ->", m)
            
    wb_df = sec_df[sec_df['log_type'] == 'web_block']
    print(f"\nTotal web_block messages: {len(wb_df)}")
    print(f"Unique web_block destinations: {wb_df['message'].nunique()}")
    print("Top web_block domains:")
    print(wb_df['message'].value_counts().head(10))
    
    # Check endpoints overlap
    sec_eps = set(sec_df['endpoint_id'].unique())
    usb_df = pd.read_csv(os.path.join(data_dir, "usb_events.csv"))
    usb_eps = set(usb_df['endpoint_id'].unique())
    print(f"\nEndpoints in Security: {len(sec_eps)}")
    print(f"Endpoints in USB: {len(usb_eps)}: {usb_eps}")
    print(f"USB endpoints in Security: {usb_eps.intersection(sec_eps)}")
    
    # Check time ranges
    print("\n=== TIME RANGES ===")
    print("USB event_time range:", usb_df['event_time'].min(), "to", usb_df['event_time'].max())
    print("Security event_time range:", sec_df['event_time'].min(), "to", sec_df['event_time'].max())
    
    # Let's inspect web activity with a fast generator
    print("\n=== WEB ACTIVITY ANALYSIS ===")
    web_file = os.path.join(data_dir, "web_activity.csv")
    dest_counter = Counter()
    ep_dest_counter = Counter()
    ep_event_counter = Counter()
    first_times = {}
    last_times = {}
    
    total_rows = 0
    # Sample or read chunks
    chunk_size = 500000
    for chunk in pd.read_csv(web_file, chunksize=chunk_size, usecols=['endpoint_id', 'event_time', 'received_time', 'message']):
        total_rows += len(chunk)
        dest_counter.update(chunk['message'].dropna())
        ep_event_counter.update(chunk['endpoint_id'].dropna())
        print(f"  Processed {total_rows} rows...")
        
    print(f"Total web rows: {total_rows}")
    print(f"Unique web destinations: {len(dest_counter)}")
    print(f"Unique web endpoints: {len(ep_event_counter)}")
    print("\nTop 20 most frequent web destinations:")
    for dest, count in dest_counter.most_common(20):
        print(f"  {dest:35s} : {count}")
        
    # Destinations appearing exactly once (rare / singleton destinations)
    singletons = sum(1 for cnt in dest_counter.values() if cnt == 1)
    under_5 = sum(1 for cnt in dest_counter.values() if cnt < 5)
    print(f"\nDestinations appearing only 1 time across all 2.8M logs: {singletons} ({singletons/len(dest_counter)*100:.1f}%)")
    print(f"Destinations appearing < 5 times: {under_5} ({under_5/len(dest_counter)*100:.1f}%)")

if __name__ == "__main__":
    inspect_details()
