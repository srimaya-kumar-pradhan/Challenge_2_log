# FORENSIC EVIDENCE LEDGER: AUDITABLE CHAIN OF EVIDENCE
### Organisation X Cyber Triage System &bull; Technical & Legal Traceability Matrix

> **Standard of Proof:** Every finding is mapped directly to its underlying raw CSV line number, timestamp, endpoint, and Cypher/GQL query. Epistemic types distinguish **FACT** (observed), **INFERENCE** (deduced), **HYPOTHESIS** (proposed scenario), **ANOMALY** (statistical outlier), and **ANALYST ASSESSMENT** (professional judgment).

---

| Claim ID | Type | Category | Claim Statement | Target Host | Source File & Line | Event Timestamp | Raw Evidence Snippet |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CLM-001** | `FACT` | Data Integrity | The web activity telemetry file is untampered, immutable, and authentic. | `FLEET-WIDE` | `Data/web_activity.csv`<br>(Line 2 of SHA256SUMS (Entire File: 2,812,119 lines)) | `10-09-2026 to 21-09-2026` | <pre style='font-size:10px;'>db90087e2eacc0b0fe7b670993cd4267bd5d9b8e258704e4ab165aa793f05ed3 data/web_activity.csv...</pre> |
| **CLM-002** | `FACT` | Data Integrity | The endpoint security telemetry file is untampered and authentic. | `FLEET-WIDE` | `Data/endpoint_security.csv`<br>(Line 3 of SHA256SUMS (Entire File: 23,541 lines)) | `01-09-2026 to 26-09-2026` | <pre style='font-size:10px;'>4eec010c1852cc0b1382debf335e69a819fac168005f8a3393f880fbc86252a1 data/endpoint_security.cs...</pre> |
| **CLM-003** | `FACT` | Data Integrity | The USB peripheral monitoring telemetry file is untampered and authentic. | `FLEET-WIDE` | `Data/usb_events.csv`<br>(Line 4 of SHA256SUMS (Entire File: 9 lines)) | `07-09-2026 to 22-09-2026` | <pre style='font-size:10px;'>8c92bfad3a2fb7f8c2c8148d4e91e44946b1536f3b693e3309e71eac8942d194 data/usb_events.csv...</pre> |
| **CLM-004** | `FACT` | Web Activity / Initial Access | Host EPJ76RZV accessed Google Drive/Apps document viewer infrastructure 2 minutes prior to malware quarantine. | `EPJ76RZV` | `Data/web_activity.csv`<br>(Line 984526 & Line 984553) | `14-09-2026 08:25:39 (Received: 14-09-2026 13:18:02)` | <pre style='font-size:10px;'>EPJ76RZV,host-aedd,9E:85:42:C3:B1:56,unit-alpha,web,14-09-2026 08:25:39,14-09-2026 13:18:0...</pre> |
| **CLM-005** | `FACT` | Malware Quarantine Detections | Antivirus quarantined weaponized spreadsheet lure 'COMPRESSED FINAL COMPARISION RETIREES WELFARE1.xlsx'. | `EPJ76RZV` | `Data/endpoint_security.csv`<br>(Line 11820 (First Scan confirmation)) | `14-09-2026 13:30:13 (Local Quarantine: 2026-09-14 08:28)` | <pre style='font-size:10px;'>EPJ76RZV,host-aedd,9E:85:42:C3:B1:56,unit-alpha,quarantine,14-09-2026 13:30:13,14-09-2026 ...</pre> |
| **CLM-006** | `FACT` | Artifact Persistence & Re-Scan | Antivirus scanner repeatedly re-listed the identical quarantined Excel file during subsequent periodic scans. | `EPJ76RZV` | `Data/endpoint_security.csv`<br>(Line 11961 (Scan 2) & Line 12508 (Scan 3)) | `14-09-2026 14:35:07 & 15-09-2026 09:58:12` | <pre style='font-size:10px;'>EPJ76RZV,...,quarantine,14-09-2026 14:35:07,...,File: COMPRESSED FINAL COMPARISION RETIREE...</pre> |
| **CLM-007** | `FACT` | Secondary Infection Attempt | A second distinct quarantine event for the same Excel file occurred 5 days later on EPJ76RZV. | `EPJ76RZV` | `Data/endpoint_security.csv`<br>(Line 18492) | `21-09-2026 15:12:40 (Local Quarantine: 2026-09-19 16:33)` | <pre style='font-size:10px;'>EPJ76RZV,...,quarantine,21-09-2026 15:12:40,...,File: COMPRESSED FINAL COMPARISION RETIREE...</pre> |
| **CLM-008** | `INFERENCE` | Attack Path Reconstruction | Endpoint EPJ76RZV was compromised via spear-phishing utilizing a cloud-hosted weaponized retirement spreadsheet. | `EPJ76RZV` | `Data/web_activity.csv & Data/endpoint_security.csv`<br>(Lines 984526, 984553 & Line 11820) | `14-09-2026 08:25:39 to 08:28:00` | <pre style='font-size:10px;'>Google Apps Viewer (08:25:39) -> ClamAV Malicious Quarantine (08:28:00, delta: +2m 21s)...</pre> |
| **CLM-009** | `FACT` | Web Activity / Pre-Incident Egress | Host EPAJI3E5 contacted Zoho public document sharing infrastructure. | `EPAJI3E5` | `Data/web_activity.csv`<br>(Line 1210889) | `14-09-2026 17:20:13 (and 17-09-2026 pre-quarantine window)` | <pre style='font-size:10px;'>EPAJI3E5,host-f6a4,F2:07:5D:2A:72:97,unit-oscar,web,14-09-2026 17:20:13,15-09-2026 05:41:2...</pre> |
| **CLM-010** | `FACT` | Malware Quarantine Detections | Antivirus quarantined two weaponized document lures in rapid succession on EPAJI3E5. | `EPAJI3E5` | `Data/endpoint_security.csv`<br>(Line 15259 & Line 15260) | `17-09-2026 16:43:44 (Local Quarantine: 12:44 & 12:59)` | <pre style='font-size:10px;'>File: Lakeside traders.docx | Quarantined At: 2026-09-17 12:44 | FileType: Malicious | SHA...</pre> |
| **CLM-011** | `FACT` | Malware Quarantine Detections | Antivirus quarantined four sequentially numbered malicious PDF files on EPMVZYZO. | `EPMVZYZO` | `Data/endpoint_security.csv`<br>(Lines 11184, 11193, 11194, 11195) | `13-09-2026 17:27:55 (Local Quarantine: 12-09-2026 09:23 to 16:26)` | <pre style='font-size:10px;'>File: mydoc-75.pdf (09:23), mydoc.pdf (10:06), mydoc-9.pdf (16:24), mydoc-10.pdf (16:26) |...</pre> |
| **CLM-012** | `FACT` | Malware Quarantine Detections | Antivirus quarantined weaponized government lure '12th Plan Works Dashboard.pdf' on EPRD7FJT. | `EPRD7FJT` | `Data/endpoint_security.csv`<br>(Line 10897) | `12-09-2026 08:25:09 (Local Quarantine: 2026-09-11 19:22)` | <pre style='font-size:10px;'>EPRD7FJT,host-916a,3E:C4:03:FE:FC:5C,unit-romeo,quarantine,12-09-2026 08:25:09,12-09-2026 ...</pre> |
| **CLM-013** | `FACT` | Desktop Artifact Cluster | Antivirus quarantined 'recently-used.xbel' across 18 endpoints, including 6 temporally correlated hosts. | `EPC2L3UH, EPJYEC7F, EPOC6Y4R, EPLDM6PE, EPDRB236, EP3GALVS` | `Data/endpoint_security.csv`<br>(Multiple Lines (e.g. EPC2L3UH Line 10421, EPJYEC7F Line 13180, EPLDM6PE Line 14210)) | `11-09-2026 to 21-09-2026` | <pre style='font-size:10px;'>File: recently-used.xbel | FileType: Malicious | SHA256: 5e10b3490160cca0fc872f2b026d4b40b...</pre> |
| **CLM-014** | `INFERENCE` | Artifact Mechanics | Quarantine of 'recently-used.xbel' is an execution artifact generated when users opened weaponized documents. | `CLUSTER (6 Hosts)` | `Data/endpoint_security.csv`<br>(Derived from ~/.local/share/recently-used.xbel OS mechanics) | `11-09-2026 to 21-09-2026` | <pre style='font-size:10px;'>Desktop XML file storing <bookmark href='file:///...'> references upon document opening in...</pre> |
| **CLM-015** | `FACT` | USB Peripheral Audit | Host EPD24DBC attached an unauthorized Mass Storage UDisk on 22 September 2026. | `EPD24DBC` | `Data/usb_events.csv`<br>(Lines 2, 3, 4, 5) | `22-09-2026 18:23:12 (Received: 22-09-2026 19:03:03)` | <pre style='font-size:10px;'>EPD24DBC,host-7394,6E:DE:00:D5:9F:8A,unit-foxtrot,usb,22-09-2026 18:23:12,22-09-2026 19:03...</pre> |
| **CLM-016** | `FACT` | USB Peripheral Audit | Host EP7FZ2XY attached a standard Logitech USB Optical Mouse (HID). | `EP7FZ2XY` | `Data/usb_events.csv`<br>(Lines 6, 7, 8, 9) | `07-09-2026 22:34:11 (Received: 07-09-2026 09:03:19)` | <pre style='font-size:10px;'>EP7FZ2XY,host-9764,F6:6F:85:06:00:26,unit-quebec,usb,07-09-2026 22:34:11,07-09-2026 09:03:...</pre> |
| **CLM-017** | `ANALYST ASSESSMENT` | Attack Vector Attribution | USB telemetry did not establish an infection connection to the 10 web-correlated compromised endpoints. | `EPD24DBC & EP7FZ2XY` | `Data/usb_events.csv & Data/endpoint_security.csv`<br>(Cross-correlation across all 23,540 security rows) | `September 2026` | <pre style='font-size:10px;'>EPD24DBC security row count = 0; EP7FZ2XY malicious quarantine count = 0....</pre> |
| **CLM-018** | `ANOMALY` | Machine Learning | Isolation Forest identified 25 behaviorally unusual endpoints across fleet activity vectors. | `FLEET-WIDE (Top: EPMVZYZO, EPC2L3UH, EP4YIFHV)` | `processed/endpoint_features.csv`<br>(Generated by Scikit-Learn IsolationForest (Contamination = 0.10)) | `Computed on September 2026 Baseline Matrix` | <pre style='font-size:10px;'>is_behavioral_anomaly = True for 25 endpoints; highest score: 1.00 (EP4YIFHV, EPMVZYZO)...</pre> |
| **CLM-019** | `ANALYST ASSESSMENT` | Triage Prioritization | Endpoints EPMVZYZO, EPC2L3UH, and EPJYEC7F are assigned CRITICAL investigation priority. | `EPMVZYZO, EPC2L3UH, EPJYEC7F` | `outputs/investigation_priority_queue.csv`<br>(Rows 1, 2, 3 of outputs/investigation_priority_queue.csv) | `September 2026` | <pre style='font-size:10px;'>EPMVZYZO (Score: 76.8, Tier: CRITICAL) | EPC2L3UH (Score: 73.8, Tier: CRITICAL) | EPJYEC7F...</pre> |
| **CLM-020** | `FACT` | Web Policy Blocks | Web filter proxy blocked 914 egress attempts across 74 endpoints targeting policy-restricted domains. | `74 Endpoints` | `Data/endpoint_security.csv`<br>(All rows where log_type == 'web_block' (914 rows)) | `01-09-2026 to 26-09-2026` | <pre style='font-size:10px;'>Top blocked: www.googleapis.com (347), www.facebook.com (179), api.ipify.org (142), www.li...</pre> |


---

## HOW TO RUN DASHBOARDS AND GQL VISUALIZATIONS

### 1. Interactive SOC Web Console (Zero-Dependency Browser Visualization)
Double-click `web_dashboard/index.html` in any browser or launch a local web server:
```bash
python -m http.server 8080 --directory web_dashboard
```
- Open: `http://localhost:8080`
- Navigate to **Evidence Ledger** tab for auditable CSV line pointers.
- Navigate to **Evidence Graph** tab for dynamic multi-hop Canvas visualization.

### 2. Neo4j Graph Database & GQL / Cypher Visualizations
To run the live Neo4j database via Docker:
```bash
docker compose up -d neo4j
```
- Open Neo4j Browser: `http://localhost:7474` (Auth: `neo4j` / `password123`)
- Execute Ingestion: Run script in `neo4j/schema.cypher`
- **Primary GQL Attack Path Query:**
```cypher
MATCH path = (e:Endpoint {endpoint_id: 'EPJ76RZV'})-[]-(n)
RETURN path;
```
- **Multi-Host Artifact Spread Query:**
```cypher
MATCH (e:Endpoint)-[q:QUARANTINED]->(f:File)-[:HAS_HASH]->(h:SHA256)
WHERE q.is_malicious = true
RETURN e, q, f, h;
```

### 3. Grafana Enterprise SOC Dashboard
```bash
docker compose up -d grafana
```
- Open Grafana: `http://localhost:3000` (Auth: `admin` / `admin`)
- Open dashboard: `Cyber Security Operations / Explainable Graph-Based Cyber Triage Dashboard`
- Filter by tier: `$tier = CRITICAL` or `$tier = HIGH`.
