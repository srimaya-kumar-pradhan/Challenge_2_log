"""
Master Autonomous Pipeline Orchestrator
Execute the complete, end-to-end, explainable cyber triage workflow:
Integrity -> Parsing -> Web Analysis -> Quarantine Deduplication -> USB Telemetry ->
Temporal Correlation -> Feature Engineering -> ML Anomaly Detection -> Triage Engine ->
Graph Export -> Automated Validation.
"""

import os
import sys
import io
import time
import yaml
import pandas as pd
from typing import Dict, Any

# Ensure stdout handles UTF-8 on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Import core pipeline modules
from src.integrity import verify_dataset_integrity
from src.parsing import load_usb_events, load_endpoint_security
from src.quarantine import parse_quarantine_logs
from src.web_analysis import analyze_web_activity, analyze_web_blocks
from src.usb_analysis import analyze_usb_events
from src.correlation import perform_temporal_correlation, correlate_usb_with_incidents
from src.features import build_endpoint_feature_matrix
from src.anomaly_detection import train_isolation_forest
from src.triage import calculate_investigation_priority
from src.graph_export import export_graph_csvs, generate_cypher_scripts, ingest_to_live_neo4j
from src.validation import validate_pipeline_outputs
from src.evidence_ledger import generate_evidence_ledger

def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def run_pipeline():
    start_time = time.time()
    print("=" * 70)
    print("  EXPLAINABLE GRAPH-BASED CYBER TRIAGE SYSTEM - MASTER PIPELINE")
    print("  Organisation X - Endpoint Telemetry Assessment")
    print("=" * 70)

    # Load configuration
    cfg = load_config()
    raw_dir = cfg['data']['raw_dir']
    processed_dir = cfg['data']['processed_dir']
    outputs_dir = cfg['data']['outputs_dir']
    neo4j_csv_dir = cfg['data']['neo4j_export_dir']
    reports_dir = cfg['data']['reports_dir']

    os.makedirs(processed_dir, exist_ok=True)
    os.makedirs(outputs_dir, exist_ok=True)
    os.makedirs(neo4j_csv_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    # -------------------------------------------------------------
    # STAGE 1: Cryptographic Integrity Verification
    # -------------------------------------------------------------
    print("\n[STAGE 1/9] Verifying Raw Telemetry SHA-256 Hashes...")
    integ = verify_dataset_integrity(raw_dir=raw_dir)
    for res in integ["results"]:
        status_lbl = "[PASS]" if res["status"] == "VERIFIED" else "[FAIL]"
        print(f"  {status_lbl} {res['filename']:24s} : {res['status']}")
    if not integ["all_passed"]:
        print("FATAL: Dataset integrity failed. Halting pipeline.")
        sys.exit(1)
    print("  -> Cryptographic integrity confirmed. Evidence files are pristine.")

    # -------------------------------------------------------------
    # STAGE 2: Security & Quarantine Analysis + Deduplication
    # -------------------------------------------------------------
    print("\n[STAGE 2/9] Ingesting Endpoint Security & Deduplicating Quarantine...")
    sec_df = load_endpoint_security(raw_dir=raw_dir)
    print(f"  Loaded {len(sec_df):,} security events across {sec_df['endpoint_id'].nunique()} endpoints.")

    raw_quar, dedup_incidents, ep_quar_summary = parse_quarantine_logs(sec_df)
    print(f"  Total raw quarantine records: {len(raw_quar):,}")
    print(f"  Unique deduplicated incidents: {len(dedup_incidents):,}")
    mal_count = dedup_incidents['is_malicious'].sum()
    mal_eps = dedup_incidents[dedup_incidents['is_malicious']]['endpoint_id'].nunique()
    print(f"  Malicious signature incidents: {mal_count} across {mal_eps} distinct endpoints.")

    raw_quar.to_csv(os.path.join(processed_dir, "quarantine_raw_parsed.csv"), index=False)
    dedup_incidents.to_csv(os.path.join(processed_dir, "quarantine_incidents_dedup.csv"), index=False)
    ep_quar_summary.to_csv(os.path.join(processed_dir, "endpoint_quarantine_summary.csv"), index=False)

    # Web Filter Blocks
    ep_web_blocks = analyze_web_blocks(sec_df)
    print(f"  Endpoints triggering web filter policy blocks: {len(ep_web_blocks)}")

    # -------------------------------------------------------------
    # STAGE 3: USB Peripheral Analysis
    # -------------------------------------------------------------
    print("\n[STAGE 3/9] Processing USB Device Telemetry...")
    usb_df = load_usb_events(raw_dir=raw_dir)
    parsed_usb, ep_usb_summary = analyze_usb_events(usb_df, sec_df['endpoint_id'])
    print(f"  Loaded {len(parsed_usb)} USB attachment records.")
    for idx, u in parsed_usb.drop_duplicates(subset=['endpoint_id', 'vid_pid']).iterrows():
        storage_tag = "[MASS STORAGE]" if u['is_mass_storage'] else "[PERIPHERAL]"
        print(f"  -> {u['endpoint_id']}: {u['raw_message'].strip()} {storage_tag}")

    parsed_usb.to_csv(os.path.join(processed_dir, "usb_events_parsed.csv"), index=False)
    ep_usb_summary.to_csv(os.path.join(processed_dir, "endpoint_usb_summary.csv"), index=False)

    # -------------------------------------------------------------
    # STAGE 4: Web Activity Profiling & Rarity Distribution
    # -------------------------------------------------------------
    print("\n[STAGE 4/9] Processing 2.8M Web Activity Logs (Chunked)...")
    rare_thresh = cfg['web_analysis']['rare_threshold_global']
    chunk_sz = cfg['parsing']['chunk_size']
    ep_web_summary, rare_dests_df, global_dest_counts = analyze_web_activity(
        raw_dir=raw_dir, chunk_size=chunk_sz, rare_threshold=rare_thresh
    )
    print(f"  Fleet web activity profiled across {len(ep_web_summary)} endpoints.")
    print(f"  Rare destinations (<{rare_thresh} fleet hits): {len(rare_dests_df):,}")

    ep_web_summary.to_csv(os.path.join(processed_dir, "endpoint_web_summary.csv"), index=False)
    rare_dests_df.to_csv(os.path.join(processed_dir, "rare_destinations.csv"), index=False)

    # -------------------------------------------------------------
    # STAGE 5: Cross-Source Temporal Correlation
    # -------------------------------------------------------------
    print("\n[STAGE 5/9] Correlating Incidents with Preceding Web Activity...")
    win_before = cfg['correlation']['window_before_minutes']
    win_after = cfg['correlation']['window_after_minutes']
    corr_incidents, corr_web_events = perform_temporal_correlation(
        dedup_incidents_df=dedup_incidents,
        raw_dir=raw_dir,
        global_dest_counts=global_dest_counts,
        window_before_mins=win_before,
        window_after_mins=win_after,
        rare_threshold=rare_thresh
    )
    corr_eps_count = corr_incidents['endpoint_id'].nunique() if not corr_incidents.empty else 0
    print(f"  Correlated {len(corr_incidents)} incidents across {corr_eps_count} endpoints within {win_before}m window.")

    if not corr_incidents.empty:
        corr_incidents.to_csv(os.path.join(processed_dir, "correlated_incidents.csv"), index=False)
    if not corr_web_events.empty:
        corr_web_events.to_csv(os.path.join(processed_dir, "correlated_web_events.csv"), index=False)

    # USB Correlation
    usb_corr = correlate_usb_with_incidents(parsed_usb, dedup_incidents)
    usb_corr.to_csv(os.path.join(processed_dir, "usb_security_correlation.csv"), index=False)

    # -------------------------------------------------------------
    # STAGE 6: Feature Engineering Matrix
    # -------------------------------------------------------------
    print("\n[STAGE 6/9] Building Interpretable Endpoint Feature Matrix...")
    # Fleet endpoints union
    all_fleet_eps = list(set(sec_df['endpoint_id'].unique()).union(set(ep_web_summary['endpoint_id'].unique())))
    feat_matrix = build_endpoint_feature_matrix(
        all_endpoints=all_fleet_eps,
        ep_quar_summary=ep_quar_summary,
        ep_web_summary=ep_web_summary,
        ep_web_blocks=ep_web_blocks,
        ep_usb_summary=ep_usb_summary,
        corr_incidents=corr_incidents
    )
    print(f"  Constructed feature matrix: {feat_matrix.shape[0]} endpoints x {feat_matrix.shape[1]} features.")

    # -------------------------------------------------------------
    # STAGE 7: Unsupervised ML Anomaly Detection (Isolation Forest)
    # -------------------------------------------------------------
    print("\n[STAGE 7/9] Running Isolation Forest Behavioral Anomaly Detection...")
    ml_features = cfg['anomaly_detection']['features']
    contamination = cfg['anomaly_detection']['contamination']
    
    scored_ml_df, iso_model, scaler = train_isolation_forest(
        feature_df=feat_matrix,
        feature_cols=ml_features,
        contamination=contamination,
        random_state=cfg['anomaly_detection']['random_state']
    )
    anom_count = scored_ml_df['is_behavioral_anomaly'].sum()
    print(f"  Isolation Forest flagged {anom_count} behaviorally anomalous endpoints (~{contamination*100:.0f}% target).")

    # -------------------------------------------------------------
    # STAGE 8: Explainable Triage Scoring & Priority Queue
    # -------------------------------------------------------------
    print("\n[STAGE 8/9] Computing Investigation Priority Scores & Tiering...")
    triage_weights = cfg['triage_scoring']['weights']
    final_triage_df = calculate_investigation_priority(scored_ml_df, weights_config=triage_weights)

    # Tier counts
    tier_dist = final_triage_df['priority_tier'].value_counts().to_dict()
    print(f"  Fleet Tier Distribution: {tier_dist}")

    # Save to outputs and processed
    final_triage_df.to_csv(os.path.join(processed_dir, "endpoint_features.csv"), index=False)
    final_triage_df.to_csv(os.path.join(outputs_dir, "investigation_priority_queue.csv"), index=False)

    print("\nTop 10 Triage Candidates:")
    top10 = final_triage_df.head(10)[[
        'endpoint_id', 'priority_tier', 'investigation_priority_score',
        'malicious_incident_count', 'temporal_correlation_count',
        'behavioral_anomaly_score', 'rare_destination_count'
    ]]
    for idx, r in top10.iterrows():
        print(f"  #{idx+1:02d} [{r['priority_tier']:8s}] {r['endpoint_id']:10s} | Score: {r['investigation_priority_score']:5.1f} | MalInc: {int(r['malicious_incident_count'])} | Corr: {int(r['temporal_correlation_count'])} | Anomaly: {r['behavioral_anomaly_score']:.2f}")

    # -------------------------------------------------------------
    # STAGE 9: Neo4j Graph Model Export & Validation Audit
    # -------------------------------------------------------------
    print("\n[STAGE 9/9] Generating Neo4j Graph Model & Automated Validation...")
    generate_cypher_scripts(neo4j_dir="neo4j")
    exported_csvs = export_graph_csvs(
        output_dir=neo4j_csv_dir,
        endpoints_df=final_triage_df,
        quar_incidents_df=dedup_incidents,
        corr_web_events_df=corr_web_events,
        parsed_usb_df=parsed_usb,
        sec_raw_df=sec_df
    )
    
    # Try connecting to live Neo4j instance if running
    neo4j_live = ingest_to_live_neo4j(
        csv_dir=neo4j_csv_dir,
        uri=cfg['neo4j']['uri'],
        user=cfg['neo4j']['user'],
        password=cfg['neo4j']['password']
    )

    # Automated Validation Quality Gates
    audit = validate_pipeline_outputs(processed_dir=processed_dir, outputs_dir=outputs_dir, neo4j_csv_dir=neo4j_csv_dir)
    print("\n" + "=" * 60)
    print("AUTOMATED PIPELINE VALIDATION AUDIT RESULTS")
    print("=" * 60)
    for c in audit["checks"]:
        print(f"  [{c['status']}] {c['check']:35s} : {c['actual']}")
    print("=" * 60)
    if not audit["passed"]:
        print("WARNING: Quality gate reported invariant failure!")
    else:
        print("ALL QUALITY GATES PASSED DETERMINISTICALLY.")

    # -------------------------------------------------------------
    # STAGE 10: Forensic Evidence Ledger Generation
    # -------------------------------------------------------------
    print("\n[STAGE 10/10] Compiling Auditable Forensic Evidence Ledger...")
    ledger_df = generate_evidence_ledger(raw_dir=raw_dir, outputs_dir=outputs_dir, reports_dir=reports_dir)
    print(f"  Compiled {len(ledger_df)} forensic claims with raw CSV line pointers and GQL queries.")

    elapsed = round(time.time() - start_time, 2)
    print(f"\nPipeline finished in {elapsed} seconds.")
    return final_triage_df

if __name__ == "__main__":
    run_pipeline()
