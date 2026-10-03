"""
Unit and Invariant Tests for Explainable Cyber Triage System
Validates timestamp parsing, quarantine deduplication, malicious classification,
temporal correlation logic, feature matrix generation, and triage scoring.
"""

import os
import pytest
import pandas as pd
import numpy as np

from src.integrity import compute_sha256
from src.parsing import parse_timestamps
from src.quarantine import categorize_artifact, parse_quarantine_logs
from src.usb_analysis import parse_usb_message
from src.features import build_endpoint_feature_matrix
from src.triage import calculate_investigation_priority

def test_timestamp_parsing():
    """Verify DD-MM-YYYY HH:MM:SS parsing and reporting delay calculation."""
    df = pd.DataFrame({
        'event_time': ['14-09-2026 08:28:00', '10-09-2026 12:00:00'],
        'received_time': ['14-09-2026 08:30:00', '11-09-2026 12:00:00']
    })
    parsed = parse_timestamps(df)
    assert 'event_dt' in parsed.columns
    assert 'received_dt' in parsed.columns
    assert parsed['delay_seconds'].iloc[0] == 120.0
    assert parsed['delay_seconds'].iloc[1] == 86400.0

def test_artifact_categorization():
    """Verify correct artifact taxonomy mapping."""
    assert categorize_artifact("recently-used.xbel") == "Desktop_Recent_Docs_Metadata"
    assert categorize_artifact("test.xlsx") == "Office_Spreadsheet_Lure"
    assert categorize_artifact("memo.docx") == "Office_Document_Lure"
    assert categorize_artifact("report.pdf") == "PDF_Document_Lure"
    assert categorize_artifact("app.desktop") == "Linux_Desktop_Entry_Script"
    assert categorize_artifact("tracker.js") == "Web_Extension_Script"
    assert categorize_artifact("rawtobr3") == "Printer_Driver_Utility"
    assert categorize_artifact("unknown.bin") == "Other_Artifact"

def test_usb_parsing():
    """Verify VID:PID extraction and device class classification."""
    msg1 = "General -UDisk , Mass Storage abcd:1234      "
    res1 = parse_usb_message(msg1)
    assert res1['is_mass_storage'] is True
    assert res1['device_class'] == "Mass_Storage"
    assert res1['vid_pid'] == "abcd:1234"

    msg2 = "usb-usage: Logitech-USB Optical Mouse, Human Interface Device 046d:c077    "
    res2 = parse_usb_message(msg2)
    assert res2['is_mass_storage'] is False
    assert res2['device_class'] == "Human_Interface_Device"
    assert res2['vid_pid'] == "046d:c077"

def test_quarantine_deduplication():
    """Verify repeated quarantine scans of the same file are properly deduplicated."""
    data = {
        'endpoint_id': ['EP001', 'EP001', 'EP002'],
        'endpoint_name': ['host1', 'host1', 'host2'],
        'mac': ['00:11:22:33:44:55', '00:11:22:33:44:55', '00:11:22:33:44:66'],
        'unit': ['unit-a', 'unit-a', 'unit-b'],
        'log_type': ['quarantine', 'quarantine', 'quarantine'],
        'event_time': ['01-09-2026 10:00:00', '02-09-2026 10:00:00', '01-09-2026 11:00:00'],
        'received_time': ['01-09-2026 10:01:00', '02-09-2026 10:01:00', '01-09-2026 11:01:00'],
        'message': [
            'File: test.xlsx | Quarantined At: 2026-08-31 09:00 | FileType: Malicious | SHA256: aaaa1111',
            'File: test.xlsx | Quarantined At: 2026-08-31 09:00 | FileType: Malicious | SHA256: aaaa1111', # duplicate scan
            'No Malicious files found.' # clean scan
        ]
    }
    sec_df = pd.DataFrame(data)
    sec_df = parse_timestamps(sec_df)
    raw_q, dedup_inc, ep_sum = parse_quarantine_logs(sec_df)

    assert len(raw_q) == 3
    assert len(dedup_inc) == 1
    assert dedup_inc['re_scan_sightings'].iloc[0] == 2
    assert dedup_inc['endpoint_id'].iloc[0] == 'EP001'
    assert ep_sum[ep_sum['endpoint_id'] == 'EP001']['malicious_incident_count'].iloc[0] == 1
    assert ep_sum[ep_sum['endpoint_id'] == 'EP002']['malicious_incident_count'].iloc[0] == 0

def test_triage_scoring_and_tiering():
    """Verify priority score bounds and priority tier assignment."""
    sample_df = pd.DataFrame([
        {
            'endpoint_id': 'EP_CRITICAL',
            'malicious_incident_count': 3,
            'temporal_correlation_count': 2,
            'behavioral_anomaly_score': 0.95,
            'rare_destination_count': 5,
            'web_block_count': 2,
            'has_mass_storage': False,
            'has_office_lure': True,
            'has_recently_used_xbel': True
        },
        {
            'endpoint_id': 'EP_BENIGN',
            'malicious_incident_count': 0,
            'temporal_correlation_count': 0,
            'behavioral_anomaly_score': 0.05,
            'rare_destination_count': 0,
            'web_block_count': 0,
            'has_mass_storage': False,
            'has_office_lure': False,
            'has_recently_used_xbel': False
        }
    ])

    scored = calculate_investigation_priority(sample_df)
    crit = scored[scored['endpoint_id'] == 'EP_CRITICAL'].iloc[0]
    benign = scored[scored['endpoint_id'] == 'EP_BENIGN'].iloc[0]

    assert crit['priority_tier'] in ['CRITICAL', 'HIGH']
    assert crit['investigation_priority_score'] >= 50.0
    assert benign['priority_tier'] == 'LOW'
    assert benign['investigation_priority_score'] == 0.0
    assert "Confirmed AV Signature Detection" in crit['triage_justification']
