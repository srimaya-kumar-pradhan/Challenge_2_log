"""
Parsing and Normalization Module
Loads raw CSV telemetry, parses timestamps, normalizes endpoint identifiers,
and provides structured DataFrames.
"""

import os
import pandas as pd
import numpy as np
from typing import Dict, Any, Optional, Iterator

DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"

def parse_timestamps(df: pd.DataFrame) -> pd.DataFrame:
    """
    Parse event_time and received_time columns to datetime objects.
    Calculates reporting delay in seconds (received_time - event_time).
    """
    df = df.copy()
    if 'event_time' in df.columns:
        df['event_dt'] = pd.to_datetime(df['event_time'], format=DATETIME_FORMAT, errors='coerce')
    if 'received_time' in df.columns:
        df['received_dt'] = pd.to_datetime(df['received_time'], format=DATETIME_FORMAT, errors='coerce')
        
    if 'event_dt' in df.columns and 'received_dt' in df.columns:
        df['delay_seconds'] = (df['received_dt'] - df['event_dt']).dt.total_seconds()
        
    return df

def load_usb_events(raw_dir: str = "Data", filename: str = "usb_events.csv") -> pd.DataFrame:
    """Load and parse USB monitoring telemetry."""
    path = os.path.join(raw_dir, filename)
    df = pd.read_csv(path)
    df = parse_timestamps(df)
    df['endpoint_id'] = df['endpoint_id'].str.strip().str.upper()
    df['unit'] = df['unit'].str.strip().str.lower()
    df['message'] = df['message'].str.strip()
    return df

def load_endpoint_security(raw_dir: str = "Data", filename: str = "endpoint_security.csv") -> pd.DataFrame:
    """Load and parse endpoint security telemetry (quarantine, av_scan, web_block)."""
    path = os.path.join(raw_dir, filename)
    df = pd.read_csv(path)
    df = parse_timestamps(df)
    df['endpoint_id'] = df['endpoint_id'].str.strip().str.upper()
    df['unit'] = df['unit'].str.strip().str.lower()
    df['log_type'] = df['log_type'].str.strip().str.lower()
    df['message'] = df['message'].str.strip()
    return df

def iterate_web_activity(raw_dir: str = "Data", filename: str = "web_activity.csv", chunk_size: int = 250000) -> Iterator[pd.DataFrame]:
    """Iterate through the 2.8M web activity rows in memory-efficient chunks."""
    path = os.path.join(raw_dir, filename)
    for chunk in pd.read_csv(path, chunksize=chunk_size):
        chunk = parse_timestamps(chunk)
        chunk['endpoint_id'] = chunk['endpoint_id'].str.strip().str.upper()
        chunk['unit'] = chunk['unit'].str.strip().str.lower()
        chunk['message'] = chunk['message'].str.strip()
        yield chunk

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    print("Testing parsing module...")
    usb = load_usb_events()
    print(f"USB loaded: {len(usb)} rows, endpoints: {usb['endpoint_id'].nunique()}")
    sec = load_endpoint_security()
    print(f"Security loaded: {len(sec)} rows, log types: {sec['log_type'].value_counts().to_dict()}")
    print("Parsing module initialized successfully.")
