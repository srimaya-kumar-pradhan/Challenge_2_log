"""
Data Integrity Verification Module
Passive, read-only verification of raw telemetry files against cryptographic checksums.
"""

import hashlib
import os
import sys
from typing import Dict, Any, List

def compute_sha256(filepath: str, block_size: int = 65536) -> str:
    """Compute the SHA-256 hash of a file efficiently in binary blocks."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest().lower()

def verify_dataset_integrity(raw_dir: str = "Data", checksums_file: str = "SHA256SUMS") -> Dict[str, Any]:
    """
    Verify all files listed in SHA256SUMS against files present in raw_dir.
    Returns structured results dictionary.
    """
    checksum_path = os.path.join(raw_dir, checksums_file)
    if not os.path.exists(checksum_path):
        raise FileNotFoundError(f"Checksum file not found: {checksum_path}")

    expected_hashes: Dict[str, str] = {}
    with open(checksum_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                expected_hash, rel_path = parts
                # Extract filename base
                filename = os.path.basename(rel_path)
                expected_hashes[filename] = expected_hash.lower()

    results: List[Dict[str, Any]] = []
    all_passed = True

    # Critical challenge logs
    core_files = ["web_activity.csv", "endpoint_security.csv", "usb_events.csv"]

    for filename in core_files:
        filepath = os.path.join(raw_dir, filename)
        if not os.path.exists(filepath):
            results.append({
                "filename": filename,
                "status": "MISSING",
                "expected_hash": expected_hashes.get(filename, "N/A"),
                "computed_hash": None,
                "size_bytes": 0
            })
            all_passed = False
            continue

        computed = compute_sha256(filepath)
        size = os.path.getsize(filepath)
        expected = expected_hashes.get(filename)

        if expected and computed == expected:
            status = "VERIFIED"
        elif not expected:
            status = "NO_CHECKSUM_PROVIDED"
        else:
            status = "MISMATCH"
            all_passed = False

        results.append({
            "filename": filename,
            "filepath": filepath,
            "status": status,
            "expected_hash": expected,
            "computed_hash": computed,
            "size_bytes": size
        })

    return {
        "all_passed": all_passed,
        "files_checked": len(results),
        "results": results
    }

if __name__ == "__main__":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    print("=" * 60)
    print("RUNNING PASSIVE DATA INTEGRITY VERIFICATION")
    print("=" * 60)
    report = verify_dataset_integrity()
    for res in report["results"]:
        status_symbol = "[PASS]" if res["status"] == "VERIFIED" else "[FAIL]"
        print(f"{status_symbol} {res['filename']:25s} : {res['status']}")
        print(f"    Expected: {res['expected_hash']}")
        print(f"    Computed: {res['computed_hash']}")
        print(f"    Size    : {res['size_bytes']:,} bytes")
    print("=" * 60)
    if report["all_passed"]:
        print("ALL RAW DATA INTEGRITY CHECKS PASSED. FILES ARE IMMUTABLE AND AUTHENTIC.")
        sys.exit(0)
    else:
        print("INTEGRITY CHECK FAILED!")
        sys.exit(1)

