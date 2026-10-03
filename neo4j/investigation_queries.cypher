// =====================================================================
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
