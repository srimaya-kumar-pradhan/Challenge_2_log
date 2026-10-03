# Explainable Graph-Based Cyber Triage System
### Organisation X Enterprise Telemetry Assessment &bull; Army Technical Internship Challenge 2

![System Status](https://img.shields.io/badge/Security_Assessment-PASS-brightgreen)
![Integrity](https://img.shields.io/badge/SHA--256-Verified-blue)
![Architecture](https://img.shields.io/badge/Architecture-Graph--ML--Explainable-purple)
![Fleet](https://img.shields.io/badge/Fleet-248_Linux_Endpoints-orange)

An autonomous, explainable, passive cybersecurity triage system built for high-security enterprise environments. The system processes millions of raw Linux endpoint logs (antivirus, quarantine, web filtering, proxy traffic, and USB telemetry), reconstructs cross-source temporal relationships, identifies compromised endpoints, and presents actionable forensic evidence via Neo4j graphs, Grafana dashboards, and an interactive SOC web console.

---

## 1. Key Operational Findings

1. **Cryptographic Integrity:** Raw evidence files matched SHA-256 hashes bit-for-bit with `Data/SHA256SUMS`.
2. **Quarantine Deduplication:** Solved the scanner directory re-listing artifact. Collapsed 20,004 raw quarantine entries into **88 true unique malicious incidents** across **33 distinct endpoints**.
3. **Cross-Source Temporal Correlation:** By correlating web activity within a 120-minute window preceding quarantine events, isolated **10 high-confidence candidate endpoints** (`EPJ76RZV`, `EPAJI3E5`, `EPMVZYZO`, `EPRD7FJT`, `EPC2L3UH`, `EPOC6Y4R`, `EPJYEC7F`, `EPLDM6PE`, `EPDRB236`, `EP3GALVS`).
4. **Primary Spear-Phishing Vectors:**
   - **`EPJ76RZV`:** Quarantined weaponized financial lure `COMPRESSED FINAL COMPARISION RETIREES WELFARE1.xlsx` (SHA: `d4a23078...`) 7.7 minutes after accessing Google Docs / Drive infrastructure (`doc-0k-74-apps-viewer.googleusercontent.com`).
   - **`EPAJI3E5`:** Targeted with dual document lures (`Lakeside traders.docx` & `Lakeside traders.pdf`) via Zoho public infrastructure.
   - **`recently-used.xbel` Cluster:** 18 endpoints had signatures quarantined from GNOME desktop history logs as users interacted with malicious documents.
5. **Physical Interface Audit (USB):** Host `EP7FZ2XY` attached a benign HID optical mouse (`046d:c077`). Host `EPD24DBC` connected a Mass Storage UDisk (`abcd:1234`), but cross-correlation proved zero security alerts on this host, confirming USB activity did not temporally align with the web document lure attacks.
6. **Defensible ML & Triage:** An unsupervised Isolation Forest anomaly engine (Contamination = 0.10) combined with a deterministic Investigation Priority Score (0–100) providing natural-language justifications for every priority assignment.

---

## 2. Architecture & Pipeline Workflow

```
[ Raw Logs: Web (2.8M) + Security (23.5K) + USB (8) ]
                         │
                         ▼
[ Stage 1: Cryptographic Integrity (SHA-256) ]
                         │
                         ▼
[ Stage 2: Telemetry Normalization & Quarantine Deduplication ]
                         │
                         ▼
[ Stage 3: Web Activity Profiling & Rarity Distribution ]
                         │
                         ▼
[ Stage 4: Cross-Source Temporal Correlation (120m Window) ]
                         │
                         ▼
[ Stage 5: Explainable Feature Engineering Matrix (248 x 26) ]
                         │
                         ▼
[ Stage 6: Unsupervised Behavioral Anomaly Detection (Isolation Forest) ]
                         │
                         ▼
[ Stage 7: Deterministic Triage Scoring & Priority Queue (0-100) ]
                         │
                         ▼
[ Stage 8: Neo4j Graph Model & Cypher Generation ]
                         │
                         ▼
[ Stage 9: Presentation: Grafana + Interactive Web Dashboard ]
```

---

## 3. Directory Structure

```
Challenge_2_LogAnalysis/
│
├── Data/                              # Raw immutable evidence
│   ├── web_activity.csv               # 2,812,118 rows (10–21 Sep 2026)
│   ├── endpoint_security.csv          # 23,540 rows (01–26 Sep 2026)
│   ├── usb_events.csv                 # 8 records
│   └── SHA256SUMS                     # Cryptographic baselines
│
├── processed/                         # Normalized, derived data tables
│   ├── quarantine_raw_parsed.csv
│   ├── quarantine_incidents_dedup.csv
│   ├── endpoint_quarantine_summary.csv
│   ├── endpoint_web_summary.csv
│   ├── rare_destinations.csv
│   ├── correlated_incidents.csv
│   ├── correlated_web_events.csv
│   ├── endpoint_usb_summary.csv
│   └── endpoint_features.csv          # Full 248 x 26 feature matrix
│
├── outputs/                           # Final triage deliverables
│   ├── investigation_priority_queue.csv
│   └── neo4j_csv/                     # 11 clean CSVs for Neo4j LOAD CSV
│
├── src/                               # Modular engineering codebase
│   ├── integrity.py                   # Passive SHA-256 verification
│   ├── parsing.py                     # Timestamps and schema normalization
│   ├── quarantine.py                  # Deduplication and artifact taxonomy
│   ├── web_analysis.py                # Shannon entropy and rarity analysis
│   ├── usb_analysis.py                # VID:PID and device classification
│   ├── correlation.py                 # Cross-source temporal correlation
│   ├── features.py                    # Feature engineering matrix builder
│   ├── anomaly_detection.py           # Isolation Forest with RobustScaler
│   ├── triage.py                      # Explainable priority scoring engine
│   ├── graph_export.py                # Neo4j CSV and Cypher export
│   └── validation.py                  # Automated quality gates and invariant audits
│
├── neo4j/                             # Graph database definitions
│   ├── constraints.cypher             # Uniqueness constraints and indexes
│   ├── schema.cypher                  # LOAD CSV ingestion script
│   └── investigation_queries.cypher   # 5 SOC investigation queries
│
├── grafana/                           # SOC dashboard configuration
│   ├── dashboards/
│   │   └── triage_investigation_dashboard.json
│   └── provisioning/
│       ├── datasources/datasources.yaml
│       └── dashboards/dashboards.yaml
│
├── web_dashboard/                     # Interactive SOC web console
│   ├── index.html                     # Standalone dashboard UI
│   ├── style.css                      # Glassmorphic dark SOC theme
│   └── app.js                         # Dynamic tables, filters, and graph canvas
│
├── reports/                           # Comprehensive documentation
│   ├── FINAL_INVESTIGATION_REPORT.md  # 24-section technical forensic report
│   └── INTERVIEW_DEFENSE_SHEET.md     # 28 core viva questions & pitch
│
├── tests/                             # Automated test suite
│   └── test_pipeline_units.py         # Unit tests (parsing, dedup, scoring)
│
├── config/
│   └── config.yaml                    # Centralized parameters and scoring weights
│
├── docker-compose.yml                 # Orchestration for Neo4j and Grafana
├── requirements.txt                   # Python dependencies
├── run_pipeline.py                    # Master pipeline orchestrator
└── README.md                          # Project documentation
```

---

## 4. Quick Start & Execution

### Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- Required packages: `pip install -r requirements.txt`

### 1. Execute the Master Pipeline
To execute the complete 9-stage pipeline from raw data to final outputs:
```bash
python run_pipeline.py
```
This automatically runs cryptographic integrity checks, log parsing, deduplication, web profiling, temporal correlation, feature engineering, Isolation Forest anomaly scoring, triage tiering, graph CSV generation, and automated validation audits.

### 2. Run Automated Tests
```bash
python -m pytest tests/test_pipeline_units.py -v
```

### 3. Launch Interactive SOC Web Dashboard
Simply open `web_dashboard/index.html` in any modern web browser:
- Instant review of all 248 fleet endpoints
- Priority queue filtering by tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- Interactive multi-hop evidence graph (Canvas visualization)
- Host deep-dive investigation with pre-incident correlated web traffic

### 4. Deploy Neo4j & Grafana (Docker)
To spin up a live Neo4j graph database and pre-provisioned Grafana dashboard:
```bash
docker compose up -d
```
- **Neo4j Browser:** `http://localhost:7474` (Auth: `neo4j` / `password123`)
  - Run queries from `neo4j/investigation_queries.cypher`
- **Grafana Dashboard:** `http://localhost:3000` (Auth: `admin` / `admin`)
  - Open `Cyber Security Operations / Explainable Graph-Based Cyber Triage Dashboard`

---

## 5. Final Quality Gate Verification Checklist

- [x] Original data untouched and immutable in `Data/`
- [x] Cryptographic SHA-256 hashes verified bit-for-bit against `SHA256SUMS`
- [x] All 2,812,118 web records, 23,540 security records, and 8 USB records parsed
- [x] Quarantine scanner re-listing deduplicated (88 unique malicious incidents across 33 endpoints)
- [x] Cross-source temporal correlation validated (10 high-priority candidates identified)
- [x] USB peripheral telemetry analyzed and correlation validated (zero infection connection)
- [x] Feature matrix engineered across all 248 endpoints with zero missing values
- [x] Machine learning pipeline reproducible (Isolation Forest with fixed random seed)
- [x] ML results explainable with individual feature attribution (no black boxes)
- [x] No unsupported compromise claims made (strict separation of FACT, INFERENCE, HYPOTHESIS, ANOMALY)
- [x] Neo4j graph model populated and exported to 11 relational CSV files
- [x] Graph relationships fully traceable to raw source row identifiers
- [x] Grafana SOC dashboard JSON model generated and pre-provisioned
- [x] Standalone interactive SOC web dashboard built with dark glassmorphic styling
- [x] Unit test suite passing (`pytest tests/test_pipeline_units.py`)
- [x] Automated pipeline validation audit passing all quality gates
- [x] Comprehensive 24-section Final Investigation Report generated (`reports/FINAL_INVESTIGATION_REPORT.md`)
- [x] 28-question Interview Defense Sheet generated (`reports/INTERVIEW_DEFENSE_SHEET.md`)
- [x] Centralized configuration documented (`config/config.yaml`)
- [x] Master pipeline single-command execution validated (`python run_pipeline.py`)
- [x] Zero external active probing or suspicious infrastructure contacted (100% passive)

---
**Lead Engineer:** Technical Project Lead & Senior Cybersecurity Engineer  
**Institution:** Army Technical Internship Assessment
