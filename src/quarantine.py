"""
Quarantine Analysis and Deduplication Module
Parses quarantine telemetry, extracts file metadata, discriminates between
actual signature matches (FileType: Malicious) vs benign/clean scans,
and handles quarantine folder re-listing deduplication.
"""

import os
import re
import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple

QUARANTINE_DT_FORMAT = "%Y-%m-%d %H:%M"

def categorize_artifact(filename: str) -> str:
    """Categorize quarantined artifact by extension/system role."""
    fn_lower = filename.lower()
    if 'recently-used.xbel' in fn_lower:
        return "Desktop_Recent_Docs_Metadata"
    elif fn_lower.endswith('.xlsx') or fn_lower.endswith('.xls'):
        return "Office_Spreadsheet_Lure"
    elif fn_lower.endswith('.docx') or fn_lower.endswith('.doc'):
        return "Office_Document_Lure"
    elif fn_lower.endswith('.pdf'):
        return "PDF_Document_Lure"
    elif fn_lower.endswith('.desktop'):
        return "Linux_Desktop_Entry_Script"
    elif fn_lower.endswith('.js'):
        return "Web_Extension_Script"
    elif 'brprint' in fn_lower or 'rawtobr' in fn_lower:
        return "Printer_Driver_Utility"
    else:
        return "Other_Artifact"

def parse_quarantine_logs(sec_df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Process security logs to extract, clean, and deduplicate quarantine events.
    
    Returns:
        1. raw_quar_df: All raw quarantine records with parsed fields.
        2. dedup_incidents_df: True unique quarantine incidents (deduplicated by endpoint, filename, quarantined_at, sha256).
        3. endpoint_summary_df: Per-endpoint aggregated quarantine indicators.
    """
    quar_mask = sec_df['log_type'] == 'quarantine'
    quar_rows = sec_df[quar_mask].copy()

    records = []
    for idx, row in quar_rows.iterrows():
        msg = str(row['message']).strip()
        is_clean_scan = ("no malicious files found" in msg.lower()) or ("no suspicious file found" in msg.lower())
        
        if is_clean_scan:
            records.append({
                "source_row_index": idx,
                "endpoint_id": row['endpoint_id'],
                "endpoint_name": row.get('endpoint_name', ''),
                "mac": row.get('mac', ''),
                "unit": row['unit'],
                "scan_event_time": row['event_time'],
                "scan_received_time": row['received_time'],
                "scan_event_dt": row.get('event_dt', pd.NaT),
                "is_clean_scan": True,
                "filename": None,
                "quarantined_at_raw": None,
                "quarantined_dt": pd.NaT,
                "file_type": None,
                "sha256": None,
                "is_malicious": False,
                "artifact_category": None,
                "raw_message": msg
            })
        elif msg.startswith("File:"):
            # Structure: File: <name> | Quarantined At: <time> | FileType: <type> | SHA256: <hash>
            parts = [p.strip() for p in msg.split('|')]
            fn, qa, ft, sha = "", "", "", ""
            for p in parts:
                if p.startswith('File:'):
                    fn = p.replace('File:', '').strip()
                elif p.startswith('Quarantined At:'):
                    qa = p.replace('Quarantined At:', '').strip()
                elif p.startswith('FileType:'):
                    ft = p.replace('FileType:', '').strip()
                elif p.startswith('SHA256:'):
                    sha = p.replace('SHA256:', '').strip().lower()
            
            is_malicious = (ft.lower() == 'malicious')
            qa_dt = pd.to_datetime(qa, format=QUARANTINE_DT_FORMAT, errors='coerce')

            records.append({
                "source_row_index": idx,
                "endpoint_id": row['endpoint_id'],
                "endpoint_name": row.get('endpoint_name', ''),
                "mac": row.get('mac', ''),
                "unit": row['unit'],
                "scan_event_time": row['event_time'],
                "scan_received_time": row['received_time'],
                "scan_event_dt": row.get('event_dt', pd.NaT),
                "is_clean_scan": False,
                "filename": fn,
                "quarantined_at_raw": qa,
                "quarantined_dt": qa_dt,
                "file_type": ft,
                "sha256": sha,
                "is_malicious": is_malicious,
                "artifact_category": categorize_artifact(fn) if fn else "Unknown",
                "raw_message": msg
            })
        else:
            # Other unformatted quarantine message
            records.append({
                "source_row_index": idx,
                "endpoint_id": row['endpoint_id'],
                "endpoint_name": row.get('endpoint_name', ''),
                "mac": row.get('mac', ''),
                "unit": row['unit'],
                "scan_event_time": row['event_time'],
                "scan_received_time": row['received_time'],
                "scan_event_dt": row.get('event_dt', pd.NaT),
                "is_clean_scan": False,
                "filename": None,
                "quarantined_at_raw": None,
                "quarantined_dt": pd.NaT,
                "file_type": "Unknown",
                "sha256": None,
                "is_malicious": False,
                "artifact_category": "Unknown",
                "raw_message": msg
            })

    raw_quar_df = pd.DataFrame(records)

    # Filter to actual file detections
    file_records = raw_quar_df[raw_quar_df['filename'].notna()].copy()

    # Deduplicate: The quarantine directory is re-scanned repeatedly during periodic scans.
    # Group by (endpoint_id, filename, quarantined_at_raw, sha256)
    dedup_rows = []
    grouped = file_records.groupby(['endpoint_id', 'filename', 'quarantined_at_raw', 'sha256'])
    
    for (ep, fn, qa, sha), group in grouped:
        first_scan = group['scan_event_dt'].min()
        last_scan = group['scan_event_dt'].max()
        scan_count = len(group)
        ft = group['file_type'].iloc[0]
        is_mal = group['is_malicious'].iloc[0]
        cat = group['artifact_category'].iloc[0]
        qa_dt = group['quarantined_dt'].iloc[0]
        unit = group['unit'].iloc[0]
        ep_name = group['endpoint_name'].iloc[0]
        first_idx = group['source_row_index'].iloc[0]
        
        dedup_rows.append({
            "incident_id": f"INC-{ep}-{sha[:8]}-{len(dedup_rows)+1:03d}",
            "source_row_index": first_idx,
            "endpoint_id": ep,
            "endpoint_name": ep_name,
            "unit": unit,
            "filename": fn,
            "quarantined_at": qa,
            "quarantined_dt": qa_dt,
            "file_type": ft,
            "sha256": sha,
            "is_malicious": is_mal,
            "artifact_category": cat,
            "re_scan_sightings": scan_count,
            "first_scan_dt": first_scan,
            "last_scan_dt": last_scan,
            "persistence_days": (last_scan - first_scan).total_seconds() / 86400.0 if pd.notna(last_scan) and pd.notna(first_scan) else 0.0
        })

    dedup_incidents_df = pd.DataFrame(dedup_rows)

    # Per-endpoint aggregated quarantine indicators
    ep_quar_summary = []
    all_eps = sec_df['endpoint_id'].unique()
    for ep in all_eps:
        ep_inc = dedup_incidents_df[dedup_incidents_df['endpoint_id'] == ep]
        mal_inc = ep_inc[ep_inc['is_malicious']]
        
        ep_quar_summary.append({
            "endpoint_id": ep,
            "total_quarantine_incidents": len(ep_inc),
            "malicious_incident_count": len(mal_inc),
            "unique_malicious_hashes": mal_inc['sha256'].nunique(),
            "unique_malicious_files": mal_inc['filename'].nunique(),
            "has_recently_used_xbel": (mal_inc['filename'] == 'recently-used.xbel').any(),
            "has_office_lure": mal_inc['artifact_category'].isin(['Office_Spreadsheet_Lure', 'Office_Document_Lure', 'PDF_Document_Lure']).any(),
            "distinct_artifact_types": ep_inc['artifact_category'].nunique()
        })

    endpoint_summary_df = pd.DataFrame(ep_quar_summary)

    return raw_quar_df, dedup_incidents_df, endpoint_summary_df

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    from parsing import load_endpoint_security
    sec = load_endpoint_security()
    raw_q, dedup_inc, ep_sum = parse_quarantine_logs(sec)
    print(f"Total raw quarantine records: {len(raw_q)}")
    print(f"Total deduplicated incidents: {len(dedup_inc)}")
    print(f"Total Malicious incidents: {dedup_inc['is_malicious'].sum()}")
    print(f"Endpoints with malicious incidents: {ep_sum[ep_sum['malicious_incident_count'] > 0]['endpoint_id'].count()}")
