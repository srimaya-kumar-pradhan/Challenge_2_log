"""
USB Monitoring and Peripheral Analysis Module
Parses USB device connection telemetry, extracts device classes (Mass Storage vs HID),
and checks for correlation with endpoint security incidents.
"""

import os
import re
import pandas as pd
from typing import Dict, Any, Tuple

def parse_usb_message(message: str) -> Dict[str, str]:
    """Parse USB message to extract device description, class, vendor_id, and product_id."""
    clean_msg = message.strip()
    
    # Check for VID:PID format (e.g., abcd:1234 or 046d:c077)
    vid_pid_match = re.search(r'([0-9a-fA-F]{4}):([0-9a-fA-F]{4})', clean_msg)
    vid = vid_pid_match.group(1).lower() if vid_pid_match else "unknown"
    pid = vid_pid_match.group(2).lower() if vid_pid_match else "unknown"
    
    # Classify device type
    if "mass storage" in clean_msg.lower() or "udisk" in clean_msg.lower() or "flash" in clean_msg.lower():
        device_class = "Mass_Storage"
        is_storage = True
    elif "human interface" in clean_msg.lower() or "mouse" in clean_msg.lower() or "keyboard" in clean_msg.lower():
        device_class = "Human_Interface_Device"
        is_storage = False
    else:
        device_class = "Other_Peripheral"
        is_storage = False
        
    return {
        "raw_message": clean_msg,
        "vendor_id": vid,
        "product_id": pid,
        "vid_pid": f"{vid}:{pid}",
        "device_class": device_class,
        "is_mass_storage": is_storage
    }

def analyze_usb_events(usb_df: pd.DataFrame, all_endpoints: pd.Series) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Process USB events and generate:
    1. parsed_usb_df: Individual USB connection events with metadata.
    2. endpoint_usb_summary_df: Endpoint-level USB feature summary across all endpoints.
    """
    parsed_records = []
    for idx, row in usb_df.iterrows():
        meta = parse_usb_message(str(row['message']))
        parsed_records.append({
            "source_row_index": idx,
            "endpoint_id": row['endpoint_id'],
            "endpoint_name": row.get('endpoint_name', ''),
            "mac": row.get('mac', ''),
            "unit": row['unit'],
            "event_time": row['event_time'],
            "event_dt": row.get('event_dt', pd.NaT),
            "received_time": row['received_time'],
            "received_dt": row.get('received_dt', pd.NaT),
            "device_class": meta['device_class'],
            "is_mass_storage": meta['is_mass_storage'],
            "vid_pid": meta['vid_pid'],
            "vendor_id": meta['vendor_id'],
            "product_id": meta['product_id'],
            "raw_message": meta['raw_message']
        })
        
    parsed_usb_df = pd.DataFrame(parsed_records)

    # Endpoint level aggregation
    summary_rows = []
    for ep in all_endpoints.unique():
        ep_usb = parsed_usb_df[parsed_usb_df['endpoint_id'] == ep]
        if len(ep_usb) > 0:
            summary_rows.append({
                "endpoint_id": ep,
                "usb_event_count": len(ep_usb),
                "has_usb_activity": True,
                "has_mass_storage": ep_usb['is_mass_storage'].any(),
                "mass_storage_event_count": ep_usb['is_mass_storage'].sum(),
                "connected_devices": ", ".join(ep_usb['vid_pid'].unique()),
                "last_usb_event_dt": ep_usb['event_dt'].max()
            })
        else:
            summary_rows.append({
                "endpoint_id": ep,
                "usb_event_count": 0,
                "has_usb_activity": False,
                "has_mass_storage": False,
                "mass_storage_event_count": 0,
                "connected_devices": "None",
                "last_usb_event_dt": pd.NaT
            })
            
    endpoint_usb_summary_df = pd.DataFrame(summary_rows)
    return parsed_usb_df, endpoint_usb_summary_df

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    from parsing import load_usb_events
    usb = load_usb_events()
    parsed_usb, ep_usb = analyze_usb_events(usb, usb['endpoint_id'])
    print(parsed_usb[['endpoint_id', 'device_class', 'vid_pid', 'event_time']])
    print(ep_usb)
