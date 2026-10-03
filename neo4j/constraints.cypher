// =====================================================================
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
