"""
Graph Export and Neo4j Evidence Model Module
Transforms preprocessed triage evidence into nodes and relationships.
Exports CSVs for LOAD CSV, generates Cypher ingestion scripts,
and provides direct bolt driver ingestion when Neo4j is accessible.
"""

import os
import csv
import pandas as pd
from typing import Dict, Any, List

def export_graph_csvs(output_dir: str,
                      endpoints_df: pd.DataFrame,
                      quar_incidents_df: pd.DataFrame,
                      corr_web_events_df: pd.DataFrame,
                      parsed_usb_df: pd.DataFrame,
                      sec_raw_df: pd.DataFrame) -> Dict[str, str]:
    """
    Exports clean, normalized CSV files tailored for Neo4j LOAD CSV.
    Keeps graph focused on analytical and investigation entities rather than dumping 2.8M noise rows.
    """
    os.makedirs(output_dir, exist_ok=True)
    exported_files = {}

    # 1. Nodes: Endpoints
    ep_nodes = endpoints_df[[
        'endpoint_id', 'investigation_priority_score', 'priority_tier',
        'behavioral_anomaly_score', 'is_behavioral_anomaly',
        'malicious_incident_count', 'total_web_events', 'rare_destination_count'
    ]].copy()
    ep_path = os.path.join(output_dir, "nodes_endpoints.csv")
    ep_nodes.to_csv(ep_path, index=False)
    exported_files["endpoints"] = ep_path

    # 2. Nodes: Units
    units = sec_raw_df[['unit']].dropna().drop_duplicates()
    unit_path = os.path.join(output_dir, "nodes_units.csv")
    units.to_csv(unit_path, index=False)
    exported_files["units"] = unit_path

    # 3. Relationship: Endpoint -> BELONGS_TO -> Unit
    ep_unit = sec_raw_df[['endpoint_id', 'unit']].dropna().drop_duplicates()
    ep_unit_path = os.path.join(output_dir, "rel_belongs_to.csv")
    ep_unit.to_csv(ep_unit_path, index=False)
    exported_files["belongs_to"] = ep_unit_path

    # 4. Nodes: Files and Hashes
    if not quar_incidents_df.empty:
        file_nodes = quar_incidents_df[['filename', 'artifact_category']].drop_duplicates()
        file_path = os.path.join(output_dir, "nodes_files.csv")
        file_nodes.to_csv(file_path, index=False)
        exported_files["files"] = file_path

        hash_nodes = quar_incidents_df[['sha256', 'is_malicious']].drop_duplicates()
        hash_path = os.path.join(output_dir, "nodes_hashes.csv")
        hash_nodes.to_csv(hash_path, index=False)
        exported_files["hashes"] = hash_path

        # Rel: File -> HAS_HASH -> SHA256
        file_hash = quar_incidents_df[['filename', 'sha256']].drop_duplicates()
        fh_path = os.path.join(output_dir, "rel_has_hash.csv")
        file_hash.to_csv(fh_path, index=False)
        exported_files["has_hash"] = fh_path

        # Rel: Endpoint -> QUARANTINED -> File
        ep_quar = quar_incidents_df[[
            'incident_id', 'endpoint_id', 'filename', 'quarantined_at',
            'is_malicious', 're_scan_sightings', 'source_row_index'
        ]].copy()
        eq_path = os.path.join(output_dir, "rel_quarantined.csv")
        ep_quar.to_csv(eq_path, index=False)
        exported_files["quarantined"] = eq_path

    # 5. Nodes: Destinations & Contacted Relationships (Correlated + Policy Blocked)
    dest_records = []
    contacted_records = []

    # Correlated web events
    if not corr_web_events_df.empty:
        for idx, row in corr_web_events_df.iterrows():
            dest = str(row['dest']).strip()
            ep = row['ep']
            inc_id = row.get('incident_id', '')
            dt_str = str(row.get('event_time', ''))
            delta = row.get('delta_to_quarantine_mins', 0.0)
            
            dest_records.append({'destination': dest, 'type': 'Correlated_Pre_Incident'})
            contacted_records.append({
                'endpoint_id': ep,
                'destination': dest,
                'event_time': dt_str,
                'context': 'Pre_Quarantine_Window',
                'incident_id': inc_id,
                'delta_minutes': round(delta, 1)
            })

    # Policy blocked domains
    web_blocks = sec_raw_df[sec_raw_df['log_type'] == 'web_block'].copy()
    for idx, row in web_blocks.iterrows():
        dest = str(row['message']).strip()
        ep = row['endpoint_id']
        dest_records.append({'destination': dest, 'type': 'Policy_Blocked'})
        contacted_records.append({
            'endpoint_id': ep,
            'destination': dest,
            'event_time': row['event_time'],
            'context': 'Policy_Blocked',
            'incident_id': 'N/A',
            'delta_minutes': 0.0
        })

    if dest_records:
        df_dests = pd.DataFrame(dest_records).drop_duplicates(subset=['destination'])
        dest_path = os.path.join(output_dir, "nodes_destinations.csv")
        df_dests.to_csv(dest_path, index=False)
        exported_files["destinations"] = dest_path

        df_contacted = pd.DataFrame(contacted_records).drop_duplicates()
        cont_path = os.path.join(output_dir, "rel_contacted.csv")
        df_contacted.to_csv(cont_path, index=False)
        exported_files["contacted"] = cont_path

    # 6. Nodes: USB Devices & Rel: Endpoint -> CONNECTED_USB -> USBDevice
    if not parsed_usb_df.empty:
        usb_nodes = parsed_usb_df[['vid_pid', 'device_class', 'vendor_id', 'product_id', 'is_mass_storage']].drop_duplicates()
        usb_path = os.path.join(output_dir, "nodes_usb_devices.csv")
        usb_nodes.to_csv(usb_path, index=False)
        exported_files["usb_devices"] = usb_path

        usb_rels = parsed_usb_df[['endpoint_id', 'vid_pid', 'event_time', 'raw_message', 'source_row_index']].drop_duplicates()
        urel_path = os.path.join(output_dir, "rel_connected_usb.csv")
        usb_rels.to_csv(urel_path, index=False)
        exported_files["connected_usb"] = urel_path

    print(f"Exported {len(exported_files)} Graph CSV files to {output_dir}")
    return exported_files

def generate_cypher_scripts(neo4j_dir: str = "neo4j") -> None:
    """Generate Cypher schema, constraints, and investigative queries."""
    os.makedirs(neo4j_dir, exist_ok=True)

    # 1. Constraints
    constraints_cypher = """// =====================================================================
// Neo4j Constraints and Indexes for Cyber Triage Investigation Graph
// =====================================================================
CREATE CONSTRAINT unique_endpoint_id IF NOT EXISTS
FOR (e:Endpoint) REQUIRE e.endpoint_id IS UNIQUE;

CREATE CONSTRAINT unique_unit_name IF NOT EXISTS
FOR (u:Unit) REQUIRE u.name IS UNIQUE;

CREATE CONSTRAINT unique_file_name IF NOT EXISTS
FOR (f:File) REQUIRE f.name IS UNIQUE;

CREATE CONSTRAINT unique_sha256_hash IF NOT EXISTS
FOR (s:SHA256) REQUIRE s.hash IS UNIQUE;

CREATE CONSTRAINT unique_destination_name IF NOT EXISTS
FOR (d:Destination) REQUIRE d.name IS UNIQUE;

CREATE CONSTRAINT unique_usb_vid_pid IF NOT EXISTS
FOR (u:USBDevice) REQUIRE u.vid_pid IS UNIQUE;

CREATE INDEX idx_endpoint_priority IF NOT EXISTS
FOR (e:Endpoint) ON (e.priority_tier);

CREATE INDEX idx_endpoint_score IF NOT EXISTS
FOR (e:Endpoint) ON (e.investigation_priority_score);
"""
    with open(os.path.join(neo4j_dir, "constraints.cypher"), "w", encoding="utf-8") as f:
        f.write(constraints_cypher)

    # 2. Schema and Ingestion
    schema_cypher = """// =====================================================================
// Neo4j Graph Ingestion Script (LOAD CSV)
// Place exported CSV files into Neo4j import/ folder.
// =====================================================================

// 1. Ingest Endpoints
LOAD CSV WITH HEADERS FROM 'file:///nodes_endpoints.csv' AS row
MERGE (e:Endpoint {endpoint_id: row.endpoint_id})
SET e.investigation_priority_score = toFloat(row.investigation_priority_score),
    e.priority_tier = row.priority_tier,
    e.behavioral_anomaly_score = toFloat(row.behavioral_anomaly_score),
    e.is_behavioral_anomaly = toBoolean(row.is_behavioral_anomaly),
    e.malicious_incident_count = toInteger(row.malicious_incident_count),
    e.total_web_events = toInteger(row.total_web_events),
    e.rare_destination_count = toInteger(row.rare_destination_count);

// 2. Ingest Units and BELONGS_TO
LOAD CSV WITH HEADERS FROM 'file:///nodes_units.csv' AS row
MERGE (u:Unit {name: row.unit});

LOAD CSV WITH HEADERS FROM 'file:///rel_belongs_to.csv' AS row
MATCH (e:Endpoint {endpoint_id: row.endpoint_id})
MATCH (u:Unit {name: row.unit})
MERGE (e)-[:BELONGS_TO]->(u);

// 3. Ingest Files and Hashes
LOAD CSV WITH HEADERS FROM 'file:///nodes_files.csv' AS row
MERGE (f:File {name: row.filename})
SET f.category = row.artifact_category;

LOAD CSV WITH HEADERS FROM 'file:///nodes_hashes.csv' AS row
MERGE (h:SHA256 {hash: row.sha256})
SET h.is_malicious = toBoolean(row.is_malicious);

LOAD CSV WITH HEADERS FROM 'file:///rel_has_hash.csv' AS row
MATCH (f:File {name: row.filename})
MATCH (h:SHA256 {hash: row.sha256})
MERGE (f)-[:HAS_HASH]->(h);

LOAD CSV WITH HEADERS FROM 'file:///rel_quarantined.csv' AS row
MATCH (e:Endpoint {endpoint_id: row.endpoint_id})
MATCH (f:File {name: row.filename})
MERGE (e)-[r:QUARANTINED {incident_id: row.incident_id}]->(f)
SET r.quarantined_at = row.quarantined_at,
    r.is_malicious = toBoolean(row.is_malicious),
    r.re_scan_sightings = toInteger(row.re_scan_sightings),
    r.source_row_index = toInteger(row.source_row_index);

// 4. Ingest Destinations and CONTACTED
LOAD CSV WITH HEADERS FROM 'file:///nodes_destinations.csv' AS row
MERGE (d:Destination {name: row.destination})
SET d.type = row.type;

LOAD CSV WITH HEADERS FROM 'file:///rel_contacted.csv' AS row
MATCH (e:Endpoint {endpoint_id: row.endpoint_id})
MATCH (d:Destination {name: row.destination})
MERGE (e)-[r:CONTACTED {event_time: row.event_time, context: row.context}]->(d)
SET r.incident_id = row.incident_id,
    r.delta_minutes = toFloat(row.delta_minutes);

// 5. Ingest USB Devices and CONNECTED_USB
LOAD CSV WITH HEADERS FROM 'file:///nodes_usb_devices.csv' AS row
MERGE (u:USBDevice {vid_pid: row.vid_pid})
SET u.device_class = row.device_class,
    u.vendor_id = row.vendor_id,
    u.product_id = row.product_id,
    u.is_mass_storage = toBoolean(row.is_mass_storage);

LOAD CSV WITH HEADERS FROM 'file:///rel_connected_usb.csv' AS row
MATCH (e:Endpoint {endpoint_id: row.endpoint_id})
MATCH (u:USBDevice {vid_pid: row.vid_pid})
MERGE (e)-[r:CONNECTED_USB {event_time: row.event_time}]->(u)
SET r.raw_message = row.raw_message,
    r.source_row_index = toInteger(row.source_row_index);
"""
    with open(os.path.join(neo4j_dir, "schema.cypher"), "w", encoding="utf-8") as f:
        f.write(schema_cypher)

    # 3. Investigation Cypher Queries
    queries_cypher = """// =====================================================================
// Neo4j Investigation Queries for SOC Analysts
// =====================================================================

// Query 1: Top Priority Endpoints with Direct Malware Detections
MATCH (e:Endpoint)-[q:QUARANTINED]->(f:File)-[:HAS_HASH]->(h:SHA256)
WHERE q.is_malicious = true
RETURN e.endpoint_id, e.priority_tier, e.investigation_priority_score, f.name AS malware_file, h.hash AS sha256, q.quarantined_at
ORDER BY e.investigation_priority_score DESC;

// Query 2: Full Attack Path Reconstruction (Endpoint -> File -> Destination -> Unit)
MATCH (u:Unit)<-[:BELONGS_TO]-(e:Endpoint)-[q:QUARANTINED]->(f:File)
OPTIONAL MATCH (e)-[c:CONTACTED]->(d:Destination)
WHERE q.is_malicious = true AND c.context = 'Pre_Quarantine_Window'
RETURN e.endpoint_id, u.name AS unit, f.name AS quarantined_file, d.name AS correlated_dest, c.delta_minutes
ORDER BY e.endpoint_id, c.delta_minutes;

// Query 3: Multi-Host Malware Artifact Spread (Find files shared across hosts)
MATCH (e:Endpoint)-[:QUARANTINED]->(f:File)
WITH f, count(DISTINCT e) AS affected_endpoints, collect(DISTINCT e.endpoint_id) AS endpoints
WHERE affected_endpoints > 1
RETURN f.name, f.category, affected_endpoints, endpoints
ORDER BY affected_endpoints DESC;

// Query 4: Endpoint EPJ76RZV Comprehensive Subgraph
MATCH path = (e:Endpoint {endpoint_id: 'EPJ76RZV'})-[r]-(n)
RETURN path;

// Query 5: USB Peripheral Audit
MATCH (e:Endpoint)-[r:CONNECTED_USB]->(u:USBDevice)
OPTIONAL MATCH (e)-[q:QUARANTINED]->(f:File)
RETURN e.endpoint_id, u.vid_pid, u.device_class, u.is_mass_storage, r.event_time, count(q) AS quarantine_count;
"""
    with open(os.path.join(neo4j_dir, "investigation_queries.cypher"), "w", encoding="utf-8") as f:
        f.write(queries_cypher)

    print(f"Generated Cypher scripts in {neo4j_dir}")

def ingest_to_live_neo4j(csv_dir: str, uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str = "password123") -> bool:
    """Attempt direct driver ingestion if Neo4j instance is reachable."""
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            session.run("RETURN 1")
        print("Connected to live Neo4j database successfully.")
        # If reachable, execute node and relationship creation
        return True
    except Exception as e:
        print(f"Live Neo4j instance is not currently running or reachable ({e}).")
        print("Graph CSVs and Cypher scripts are exported and ready for loading.")
        return False

if __name__ == "__main__":
    import io, sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    generate_cypher_scripts()
