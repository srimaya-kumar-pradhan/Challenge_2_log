// =====================================================================
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
