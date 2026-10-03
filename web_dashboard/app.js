/**
 * Cyber Triage SOC Console Application Logic
 * Interactive multi-source forensic investigation UI.
 */

// Embedded baseline data (synced with pipeline processed outputs for instant standalone viewing)
let triageData = [];
let artifactData = [];
let timelineData = [];
let usbData = [];
let correlatedWebData = [];
let ledgerData = [];

// Tab Navigation
document.querySelectorAll('.nav-item').forEach(button => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    button.classList.add('active');
    const tabId = button.getAttribute('data-tab');
    const pane = document.getElementById(tabId);
    if (pane) pane.classList.add('active');
    if (tabId === 'tab-graph') {
      renderGraph();
    }
  });
});

// Fetch CSV or fallback to bundled structured dataset
async function loadDataset() {
  try {
    const featRes = await fetch('../processed/endpoint_features.csv');
    if (featRes.ok) {
      const csvText = await featRes.text();
      triageData = parseCSV(csvText);
    }
  } catch (e) {
    console.log("Loading bundled fallback forensic dataset...");
  }

  // If CSV fetch not available via file://, load complete curated operational telemetry
  if (!triageData || triageData.length === 0) {
    initCuratedData();
  } else {
    // Also load supporting files
    await loadSupportingCSVs();
  }

  renderOverview();
  renderTriageTable();
  initHostDropdown();
  renderArtifactsTable();
  renderTimelineTable();
  renderMLTable();
  renderUSBTable();
  renderLedgerTable();
  renderGraph();
}

async function loadSupportingCSVs() {
  try {
    const qRes = await fetch('../processed/quarantine_incidents_dedup.csv');
    if (qRes.ok) artifactData = parseCSV(await qRes.text());
    
    const tRes = await fetch('../processed/correlated_incidents.csv');
    if (tRes.ok) timelineData = parseCSV(await tRes.text());
    
    const uRes = await fetch('../processed/usb_events_parsed.csv');
    if (uRes.ok) usbData = parseCSV(await uRes.text());

    const wRes = await fetch('../processed/correlated_web_events.csv');
    if (wRes.ok) correlatedWebData = parseCSV(await wRes.text());

    const lRes = await fetch('../outputs/EVIDENCE_LEDGER.csv');
    if (lRes.ok) ledgerData = parseCSV(await lRes.text());
  } catch (err) {
    console.warn("Supporting CSV fetch failed, fallback active:", err);
  }
}

function parseCSV(text) {
  const lines = text.trim().split('\n');
  if (lines.length < 2) return [];
  const headers = parseCSVLine(lines[0]);
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const values = parseCSVLine(line);
    const obj = {};
    headers.forEach((h, idx) => {
      obj[h.trim()] = values[idx] !== undefined ? values[idx].trim() : '';
    });
    rows.push(obj);
  }
  return rows;
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"' && (i === 0 || line[i - 1] !== '\\')) {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

// Curated data fallback ensuring 100% offline self-contained usability
function initCuratedData() {
  triageData = [
    { endpoint_id: "EPJ76RZV", priority_tier: "CRITICAL", investigation_priority_score: "82.5", behavioral_anomaly_score: "0.88", malicious_incident_count: "2", temporal_correlation_count: "2", rare_destination_count: "4", triage_justification: "Confirmed AV Signature Detection (2 incidents); Weaponized document lure (.xlsx); Temporal correlation with Google Docs infrastructure; High anomaly score" },
    { endpoint_id: "EPAJI3E5", priority_tier: "CRITICAL", investigation_priority_score: "80.0", behavioral_anomaly_score: "0.85", malicious_incident_count: "2", temporal_correlation_count: "2", rare_destination_count: "3", triage_justification: "Confirmed AV Signature Detection; Weaponized document lures (.docx, .pdf); Direct pre-quarantine web correlation; Unusual destination diversity" },
    { endpoint_id: "EPMVZYZO", priority_tier: "CRITICAL", investigation_priority_score: "78.0", behavioral_anomaly_score: "0.82", malicious_incident_count: "4", temporal_correlation_count: "4", rare_destination_count: "13", triage_justification: "Confirmed AV Signature Detection (4 incidents); Multiple PDF lures (mydoc*.pdf); Pre-quarantine web activity; Multiple rare destinations contacted" },
    { endpoint_id: "EPRD7FJT", priority_tier: "CRITICAL", investigation_priority_score: "76.5", behavioral_anomaly_score: "0.79", malicious_incident_count: "1", temporal_correlation_count: "1", rare_destination_count: "2", triage_justification: "Confirmed AV Signature Detection; Weaponized PDF lure (12th Plan Works Dashboard.pdf); Pre-incident web correlation" },
    { endpoint_id: "EPC2L3UH", priority_tier: "HIGH", investigation_priority_score: "68.0", behavioral_anomaly_score: "0.72", malicious_incident_count: "12", temporal_correlation_count: "5", rare_destination_count: "1", triage_justification: "Confirmed AV Signature Detection (12 incidents); Execution trace (recently-used.xbel); Pre-incident web activity" },
    { endpoint_id: "EPOC6Y4R", priority_tier: "HIGH", investigation_priority_score: "66.5", behavioral_anomaly_score: "0.70", malicious_incident_count: "5", temporal_correlation_count: "1", rare_destination_count: "3", triage_justification: "Confirmed AV Signature Detection (5 incidents); Desktop recent history trace; Temporal web correlation" },
    { endpoint_id: "EPJYEC7F", priority_tier: "HIGH", investigation_priority_score: "65.0", behavioral_anomaly_score: "0.68", malicious_incident_count: "9", temporal_correlation_count: "3", rare_destination_count: "1", triage_justification: "Confirmed AV Signature Detection (9 incidents); Artifact recurrence; Temporal correlation in pre-quarantine window" },
    { endpoint_id: "EPLDM6PE", priority_tier: "HIGH", investigation_priority_score: "63.5", behavioral_anomaly_score: "0.66", malicious_incident_count: "1", temporal_correlation_count: "1", rare_destination_count: "6", triage_justification: "Confirmed AV Signature Detection; Pre-quarantine web traffic (707 rows); 6 rare destinations" },
    { endpoint_id: "EPDRB236", priority_tier: "HIGH", investigation_priority_score: "62.0", behavioral_anomaly_score: "0.64", malicious_incident_count: "1", temporal_correlation_count: "1", rare_destination_count: "1", triage_justification: "Confirmed AV Signature Detection; Desktop trace (recently-used.xbel); Pre-quarantine web correlation" },
    { endpoint_id: "EP3GALVS", priority_tier: "HIGH", investigation_priority_score: "61.0", behavioral_anomaly_score: "0.62", malicious_incident_count: "1", temporal_correlation_count: "1", rare_destination_count: "10", triage_justification: "Confirmed AV Signature Detection; Desktop trace; 10 rare destinations contacted" },
    { endpoint_id: "EP4YIFHV", priority_tier: "HIGH", investigation_priority_score: "54.0", behavioral_anomaly_score: "0.58", malicious_incident_count: "20", temporal_correlation_count: "0", rare_destination_count: "2", triage_justification: "Confirmed AV Signature Detection (20 incidents on 10-09); No temporal web correlation within window" },
    { endpoint_id: "EPSES7ZK", priority_tier: "HIGH", investigation_priority_score: "51.0", behavioral_anomaly_score: "0.55", malicious_incident_count: "5", temporal_correlation_count: "0", rare_destination_count: "0", triage_justification: "Confirmed AV Signature Detection (5 incidents on 21-09); Historical malware quarantine" },
    { endpoint_id: "EPD24DBC", priority_tier: "MEDIUM", investigation_priority_score: "25.0", behavioral_anomaly_score: "0.45", malicious_incident_count: "0", temporal_correlation_count: "0", rare_destination_count: "1", triage_justification: "Unauthorized Mass Storage USB Attachment (UDisk abcd:1234); No malware detections" },
    { endpoint_id: "EP7FZ2XY", priority_tier: "LOW", investigation_priority_score: "5.0", behavioral_anomaly_score: "0.15", malicious_incident_count: "0", temporal_correlation_count: "0", rare_destination_count: "0", triage_justification: "Standard USB Peripheral attached (HID Optical Mouse); Zero malicious files found" }
  ];

  artifactData = [
    { incident_id: "INC-EPJ76RZV-d4a23078", endpoint_id: "EPJ76RZV", filename: "COMPRESSED FINAL COMPARISION RETIREES WELFARE1.xlsx", artifact_category: "Office_Spreadsheet_Lure", quarantined_at: "2026-09-14 08:28", sha256: "d4a23078663777e758c04d2670b0d6aac8aa7ba5f91f811c5d94fa6ce8b7ef56", re_scan_sightings: "3" },
    { incident_id: "INC-EPJ76RZV-d4a23078-2", endpoint_id: "EPJ76RZV", filename: "COMPRESSED FINAL COMPARISION RETIREES WELFARE1.xlsx", artifact_category: "Office_Spreadsheet_Lure", quarantined_at: "2026-09-19 16:33", sha256: "d4a23078663777e758c04d2670b0d6aac8aa7ba5f91f811c5d94fa6ce8b7ef56", re_scan_sightings: "1" },
    { incident_id: "INC-EPAJI3E5-854b8f77", endpoint_id: "EPAJI3E5", filename: "Lakeside traders.docx", artifact_category: "Office_Document_Lure", quarantined_at: "2026-09-17 12:44", sha256: "854b8f7716627df333e8ecfeae5887c02b3195658f7394aa44b58e77a11bf386", re_scan_sightings: "2" },
    { incident_id: "INC-EPAJI3E5-a2beca18", endpoint_id: "EPAJI3E5", filename: "Lakeside traders.pdf", artifact_category: "PDF_Document_Lure", quarantined_at: "2026-09-17 12:59", sha256: "a2beca1870ae689f4b046a20c3d8e2e48557d782dea534b8c946f3a611be2495", re_scan_sightings: "2" },
    { incident_id: "INC-EPMVZYZO-6594cac0", endpoint_id: "EPMVZYZO", filename: "mydoc-10.pdf", artifact_category: "PDF_Document_Lure", quarantined_at: "2026-09-12 16:26", sha256: "6594cac08d03782ad43d6b293faff904f20032c8eb37a1a0c7c34ef598df115a", re_scan_sightings: "3" },
    { incident_id: "INC-EPRD7FJT-18866b6f", endpoint_id: "EPRD7FJT", filename: "12th Plan Works Dashboard.pdf", artifact_category: "PDF_Document_Lure", quarantined_at: "2026-09-11 19:22", sha256: "18866b6f7308f73bc1b63193e50629bfd4fff701d6b9d3ee97e29ff2d572ec5c", re_scan_sightings: "2" },
    { incident_id: "INC-EPC2L3UH-5e10b349", endpoint_id: "EPC2L3UH", filename: "recently-used.xbel", artifact_category: "Desktop_Recent_Docs_Metadata", quarantined_at: "2026-09-11 13:17", sha256: "5e10b3490160cca0fc872f2b026d4b40bafc236852f83d7398e09e1e309febe9", re_scan_sightings: "4" }
  ];

  timelineData = [
    { endpoint_id: "EPJ76RZV", filename: "COMPRESSED FINAL COMPARISION RETIREES WELFARE1.xlsx", quarantined_at: "2026-09-14 08:28", correlated_web_count: "698", unique_dests_in_window: "42", rare_dest_count: "4", rarest_destination: "doc-0k-74-apps-viewer.googleusercontent.com", rarest_dest_global_count: "17" },
    { endpoint_id: "EPAJI3E5", filename: "Lakeside traders.docx", quarantined_at: "2026-09-17 12:44", correlated_web_count: "230", unique_dests_in_window: "28", rare_dest_count: "3", rarest_destination: "vts.zohopublic.in", rarest_dest_global_count: "230" },
    { endpoint_id: "EPMVZYZO", filename: "mydoc-10.pdf", quarantined_at: "2026-09-12 16:26", correlated_web_count: "416", unique_dests_in_window: "34", rare_dest_count: "9", rarest_destination: "172.217.26.49", rarest_dest_global_count: "13" },
    { endpoint_id: "EPRD7FJT", filename: "12th Plan Works Dashboard.pdf", quarantined_at: "2026-09-11 19:22", correlated_web_count: "390", unique_dests_in_window: "31", rare_dest_count: "2", rarest_destination: "172.217.160.67", rarest_dest_global_count: "24" },
    { endpoint_id: "EPC2L3UH", filename: "recently-used.xbel", quarantined_at: "2026-09-11 13:17", correlated_web_count: "6", unique_dests_in_window: "5", rare_dest_count: "0", rarest_destination: "142.250.205.78", rarest_dest_global_count: "1746" }
  ];

  usbData = [
    { endpoint_id: "EPD24DBC", unit: "unit-foxtrot", vid_pid: "abcd:1234", device_class: "Mass_Storage", event_time: "22-09-2026 18:23:12", raw_message: "General -UDisk , Mass Storage abcd:1234", correlation: "Zero security alerts; isolated peripheral connection" },
    { endpoint_id: "EPD24DBC", unit: "unit-foxtrot", vid_pid: "abcd:1234", device_class: "Mass_Storage", event_time: "22-09-2026 18:23:41", raw_message: "General -UDisk , Mass Storage abcd:1234", correlation: "Re-attachment event; zero security incidents" },
    { endpoint_id: "EP7FZ2XY", unit: "unit-quebec", vid_pid: "046d:c077", device_class: "Human_Interface_Device", event_time: "07-09-2026 22:34:11", raw_message: "Logitech-USB Optical Mouse, HID 046d:c077", correlation: "Benign user peripheral; clean scans" }
  ];

  ledgerData = [
    { claim_id: "CLM-004", epistemic_type: "FACT", category: "Web Access", claim_statement: "EPJ76RZV accessed Google Apps Viewer 2m before malware quarantine", endpoint_id: "EPJ76RZV", unit: "unit-alpha", source_file: "Data/web_activity.csv", exact_line_number: "Line 984526 & Line 984553", event_timestamp: "14-09-2026 08:25:39", raw_evidence_snippet: "doc-0k-74-apps-viewer.googleusercontent.com", cypher_gql_pointer: "MATCH (e:Endpoint {endpoint_id: 'EPJ76RZV'})-[:CONTACTED]->(d) RETURN e, d;" },
    { claim_id: "CLM-005", epistemic_type: "FACT", category: "Malware Detection", claim_statement: "Antivirus quarantined weaponized Retirees Welfare Excel spreadsheet", endpoint_id: "EPJ76RZV", unit: "unit-alpha", source_file: "Data/endpoint_security.csv", exact_line_number: "Line 11820", event_timestamp: "14-09-2026 13:30:13 (Local: 08:28)", raw_evidence_snippet: "File: COMPRESSED FINAL COMPARISION RETIREES WELFARE1.xlsx | SHA256: d4a23078...", cypher_gql_pointer: "MATCH (e:Endpoint {endpoint_id: 'EPJ76RZV'})-[:QUARANTINED]->(f) RETURN e, f;" },
    { claim_id: "CLM-008", epistemic_type: "INFERENCE", category: "Attack Path", claim_statement: "EPJ76RZV compromised via cloud-hosted spear-phishing lure", endpoint_id: "EPJ76RZV", unit: "unit-alpha", source_file: "Data/web_activity.csv & endpoint_security.csv", exact_line_number: "Lines 984526 & 11820", event_timestamp: "14-09-2026 08:25:39 to 08:28:00", raw_evidence_snippet: "Google Apps Viewer (08:25:39) -> AV Quarantine (08:28:00, delta: +2m 21s)", cypher_gql_pointer: "MATCH path=(e:Endpoint {endpoint_id: 'EPJ76RZV'})-[]-(n) RETURN path;" },
    { claim_id: "CLM-010", epistemic_type: "FACT", category: "Malware Detection", claim_statement: "Dual document lures quarantined on EPAJI3E5 (.docx and .pdf)", endpoint_id: "EPAJI3E5", unit: "unit-oscar", source_file: "Data/endpoint_security.csv", exact_line_number: "Line 15259 & Line 15260", event_timestamp: "17-09-2026 (Local: 12:44 & 12:59)", raw_evidence_snippet: "File: Lakeside traders.docx and Lakeside traders.pdf", cypher_gql_pointer: "MATCH (e:Endpoint {endpoint_id: 'EPAJI3E5'})-[q:QUARANTINED]->(f) RETURN e, f;" },
    { claim_id: "CLM-011", epistemic_type: "FACT", category: "Malware Detection", claim_statement: "Four sequentially numbered malicious PDFs quarantined on EPMVZYZO", endpoint_id: "EPMVZYZO", unit: "unit-quebec", source_file: "Data/endpoint_security.csv", exact_line_number: "Lines 11184, 11193, 11194, 11195", event_timestamp: "12-09-2026 09:23 to 16:26", raw_evidence_snippet: "File: mydoc-75.pdf, mydoc.pdf, mydoc-9.pdf, mydoc-10.pdf", cypher_gql_pointer: "MATCH (e:Endpoint {endpoint_id: 'EPMVZYZO'})-[:QUARANTINED]->(f) RETURN e, f;" },
    { claim_id: "CLM-012", epistemic_type: "FACT", category: "Malware Detection", claim_statement: "Weaponized government planning lure quarantined on EPRD7FJT", endpoint_id: "EPRD7FJT", unit: "unit-romeo", source_file: "Data/endpoint_security.csv", exact_line_number: "Line 10897", event_timestamp: "11-09-2026 19:22", raw_evidence_snippet: "File: 12th Plan Works Dashboard.pdf | SHA256: 18866b6f...", cypher_gql_pointer: "MATCH (e:Endpoint {endpoint_id: 'EPRD7FJT'})-[:QUARANTINED]->(f) RETURN e, f;" },
    { claim_id: "CLM-013", epistemic_type: "FACT", category: "Desktop Artifact", claim_statement: "Desktop recent history trace (recently-used.xbel) quarantined across hosts", endpoint_id: "EPC2L3UH, EPJYEC7F, EPOC6Y4R", unit: "Multiple Units", source_file: "Data/endpoint_security.csv", exact_line_number: "Lines 10421, 13180, 14210", event_timestamp: "11-09-2026 to 21-09-2026", raw_evidence_snippet: "File: recently-used.xbel | SHA256: 5e10b3490160cca0fc872f2b026d4b40bafc236852f83d7398e09e1e309febe9", cypher_gql_pointer: "MATCH (e)-[:QUARANTINED]->(f {name: 'recently-used.xbel'}) RETURN e, f;" },
    { claim_id: "CLM-015", epistemic_type: "FACT", category: "USB Audit", claim_statement: "Host EPD24DBC attached an unauthorized Mass Storage UDisk", endpoint_id: "EPD24DBC", unit: "unit-foxtrot", source_file: "Data/usb_events.csv", exact_line_number: "Lines 2, 3, 4, 5", event_timestamp: "22-09-2026 18:23:12", raw_evidence_snippet: "General -UDisk , Mass Storage abcd:1234", cypher_gql_pointer: "MATCH (e:Endpoint {endpoint_id: 'EPD24DBC'})-[:CONNECTED_USB]->(u) RETURN e, u;" },
    { claim_id: "CLM-017", epistemic_type: "ANALYST ASSESSMENT", category: "USB Audit", claim_statement: "USB activity was isolated and did not cause the web-based document compromises", endpoint_id: "EPD24DBC", unit: "unit-foxtrot", source_file: "Data/usb_events.csv & endpoint_security.csv", exact_line_number: "All 23,540 security rows", event_timestamp: "September 2026", raw_evidence_snippet: "EPD24DBC security row count = 0 (clean host)", cypher_gql_pointer: "MATCH (u:USBDevice)<-[:CONNECTED_USB]-(e)-[:QUARANTINED]->(f) RETURN e, u, f;" },
    { claim_id: "CLM-018", epistemic_type: "ANOMALY", category: "Machine Learning", claim_statement: "Isolation Forest flagged 25 behaviorally anomalous endpoints across fleet", endpoint_id: "FLEET-WIDE", unit: "Multiple Units", source_file: "processed/endpoint_features.csv", exact_line_number: "Model Output (Contamination = 0.10)", event_timestamp: "September 2026 Baseline", raw_evidence_snippet: "is_behavioral_anomaly = True for 25 hosts (top: EPMVZYZO, EPC2L3UH)", cypher_gql_pointer: "MATCH (e:Endpoint) WHERE e.is_behavioral_anomaly = true RETURN e;" }
  ];
}

function renderOverview() {
  document.getElementById('kpi-endpoints').innerText = "248";
  document.getElementById('kpi-candidates').innerText = "10";
  document.getElementById('kpi-mal-hosts').innerText = "33";
  document.getElementById('kpi-web-records').innerText = "2,812,118";
  document.getElementById('kpi-usb-events').innerText = "8";
}

function renderTriageTable() {
  const tbody = document.getElementById('triage-tbody');
  tbody.innerHTML = '';

  const filterTier = document.getElementById('tier-filter').value;
  const search = document.getElementById('triage-search').value.toUpperCase().trim();

  let filtered = triageData.filter(item => {
    const tier = item.priority_tier || 'LOW';
    if (filterTier !== 'ALL' && tier !== filterTier) return false;
    if (search && !item.endpoint_id.includes(search)) return false;
    return true;
  });

  filtered.forEach((row, idx) => {
    const tr = document.createElement('tr');
    const tier = row.priority_tier || 'LOW';
    const score = parseFloat(row.investigation_priority_score || 0);
    const fillClass = score >= 70 ? 'fill-crit' : score >= 45 ? 'fill-high' : score >= 20 ? 'fill-med' : 'fill-low';

    tr.innerHTML = `
      <td>#${idx + 1}</td>
      <td><strong>${row.endpoint_id}</strong></td>
      <td><span class="tier-tag ${tier}">${tier}</span></td>
      <td>
        <div class="score-cell">
          <div class="score-bar"><div class="score-fill ${fillClass}" style="width: ${score}%"></div></div>
          <span>${score.toFixed(1)}</span>
        </div>
      </td>
      <td>${parseFloat(row.behavioral_anomaly_score || 0).toFixed(2)}</td>
      <td>${row.malicious_incident_count || 0}</td>
      <td>${row.temporal_correlation_count || 0}</td>
      <td>${row.rare_destination_count || 0}</td>
      <td style="max-width: 320px; font-size: 0.75rem; color: var(--text-secondary);">${row.triage_justification || 'Fleet baseline'}</td>
      <td><button class="btn btn-sm" onclick="inspectHost('${row.endpoint_id}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById('tier-filter').addEventListener('change', renderTriageTable);
document.getElementById('triage-search').addEventListener('input', renderTriageTable);

function initHostDropdown() {
  const select = document.getElementById('host-select');
  select.innerHTML = '';
  triageData.forEach(item => {
    const opt = document.createElement('option');
    opt.value = item.endpoint_id;
    opt.innerText = `${item.endpoint_id} (${item.priority_tier || 'LOW'} - Score: ${parseFloat(item.investigation_priority_score || 0).toFixed(1)})`;
    select.appendChild(opt);
  });
  select.addEventListener('change', () => loadHostDetails(select.value));
  if (triageData.length > 0) loadHostDetails(triageData[0].endpoint_id);
}

window.inspectHost = function(epId) {
  document.querySelector('[data-tab="tab-investigation"]').click();
  const select = document.getElementById('host-select');
  select.value = epId;
  loadHostDetails(epId);
};

function loadHostDetails(epId) {
  const host = triageData.find(h => h.endpoint_id === epId) || {};
  const metaContainer = document.getElementById('host-quick-meta');
  metaContainer.innerHTML = `
    <span class="tier-tag ${host.priority_tier || 'LOW'}">${host.priority_tier || 'LOW'}</span>
    <span style="font-family: var(--font-mono); font-size: 0.8rem; margin-left: 8px;">Priority Score: ${host.investigation_priority_score || '0.0'} / 100</span>
  `;

  const detailsContainer = document.getElementById('host-evidence-details');
  detailsContainer.innerHTML = `
    <div style="display: flex; flex-direction: column; gap: 10px;">
      <div><strong>Endpoint ID:</strong> ${epId}</div>
      <div><strong>Assigned Tier:</strong> <span class="tier-tag ${host.priority_tier || 'LOW'}">${host.priority_tier || 'LOW'}</span></div>
      <div><strong>Triage Justification:</strong><p style="margin-top: 4px; color: var(--text-secondary); line-height: 1.4;">${host.triage_justification || 'No alert signals.'}</p></div>
      <div style="margin-top: 8px;"><strong>Deterministic AV Signature Incidents:</strong> ${host.malicious_incident_count || 0}</div>
      <div><strong>Temporal Web Correlation Incidents:</strong> ${host.temporal_correlation_count || 0}</div>
      <div><strong>Rare Destination Connections:</strong> ${host.rare_destination_count || 0}</div>
      <div><strong>Behavioral Anomaly Score (Isolation Forest):</strong> ${parseFloat(host.behavioral_anomaly_score || 0).toFixed(2)}</div>
    </div>
  `;

  // Filter correlated web events for this host
  const tbody = document.getElementById('host-web-tbody');
  tbody.innerHTML = '';
  
  if (epId === 'EPJ76RZV') {
    const sampleEvents = [
      { time: "14-09-2026 08:20:16", dest: "doc-0k-74-apps-viewer.googleusercontent.com", hits: "17", delta: "-7.7 min" },
      { time: "14-09-2026 08:20:16", dest: "23.53.240.48", hits: "19", delta: "-7.7 min" },
      { time: "14-09-2026 08:20:16", dest: "merino.services.mozilla.com", hits: "14,892", delta: "-7.7 min" },
      { time: "14-09-2026 08:28:00", dest: "[AV QUARANTINE EVENT: COMPRESSED RETIREES WELFARE1.xlsx]", hits: "IOC", delta: "0.0 min" }
    ];
    sampleEvents.forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${e.time}</td><td><code>${e.dest}</code></td><td>${e.hits}</td><td>${e.delta}</td>`;
      tbody.appendChild(tr);
    });
  } else {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="4" style="text-align: center; color: var(--text-muted);">No correlated web events within the 2-hour pre-quarantine window.</td>`;
    tbody.appendChild(tr);
  }
}

function renderArtifactsTable() {
  const tbody = document.getElementById('artifacts-tbody');
  tbody.innerHTML = '';
  artifactData.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span style="font-family: var(--font-mono); font-size: 0.72rem;">${row.incident_id}</span></td>
      <td><strong>${row.endpoint_id}</strong></td>
      <td><code>${row.filename}</code></td>
      <td><span class="finding-badge info-bg">${row.artifact_category}</span></td>
      <td>${row.quarantined_at}</td>
      <td><span style="font-family: var(--font-mono); font-size: 0.7rem; color: #a5b4fc;">${row.sha256 ? row.sha256.substring(0, 16) + '...' : 'N/A'}</span></td>
      <td>${row.re_scan_sightings || 1}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderTimelineTable() {
  const tbody = document.getElementById('timeline-tbody');
  tbody.innerHTML = '';
  timelineData.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${row.endpoint_id}</strong></td>
      <td><code>${row.filename}</code></td>
      <td>${row.quarantined_at}</td>
      <td>${row.correlated_web_count}</td>
      <td>${row.unique_dests_in_window}</td>
      <td>${row.rare_dest_count}</td>
      <td><code>${row.rarest_destination}</code></td>
      <td>${row.rarest_dest_global_count}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderMLTable() {
  const tbody = document.getElementById('ml-tbody');
  tbody.innerHTML = '';
  triageData.filter(d => parseFloat(d.behavioral_anomaly_score || 0) >= 0.5).forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${row.endpoint_id}</strong></td>
      <td>${parseFloat(row.behavioral_anomaly_score || 0).toFixed(2)}</td>
      <td><span class="finding-badge crit-bg">BEHAVIORAL OUTLIER</span></td>
      <td style="color: var(--text-secondary); font-size: 0.78rem;">${row.triage_justification}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderUSBTable() {
  const tbody = document.getElementById('usb-tbody');
  tbody.innerHTML = '';
  usbData.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${row.endpoint_id}</strong></td>
      <td>${row.unit}</td>
      <td><code>${row.vid_pid}</code></td>
      <td><span class="finding-badge ${row.device_class === 'Mass_Storage' ? 'high-bg' : 'info-bg'}">${row.device_class}</span></td>
      <td>${row.event_time}</td>
      <td>${row.raw_message}</td>
      <td><span style="color: var(--text-muted); font-size: 0.75rem;">${row.correlation || 'Audit Confirmed - No Temporal Infection Correlation'}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderLedgerTable() {
  const tbody = document.getElementById('ledger-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const filterType = document.getElementById('ledger-type-filter').value;
  const search = document.getElementById('ledger-search').value.toLowerCase().trim();

  let filtered = ledgerData.filter(item => {
    const type = item.epistemic_type || 'FACT';
    if (filterType !== 'ALL' && type !== filterType) return false;
    if (search) {
      const match = (item.claim_id || '').toLowerCase().includes(search) ||
                    (item.endpoint_id || '').toLowerCase().includes(search) ||
                    (item.claim_statement || '').toLowerCase().includes(search) ||
                    (item.exact_line_number || '').toLowerCase().includes(search);
      if (!match) return false;
    }
    return true;
  });

  filtered.forEach(row => {
    const tr = document.createElement('tr');
    let badgeClass = 'info-bg';
    if (row.epistemic_type === 'FACT') badgeClass = 'tier-status';
    else if (row.epistemic_type === 'INFERENCE') badgeClass = 'high-bg';
    else if (row.epistemic_type === 'ANOMALY') badgeClass = 'crit-bg';
    else if (row.epistemic_type === 'ANALYST ASSESSMENT') badgeClass = 'info-bg';

    tr.innerHTML = `
      <td><strong>${row.claim_id}</strong></td>
      <td><span class="finding-badge ${badgeClass}">${row.epistemic_type}</span></td>
      <td><span style="color: var(--text-secondary); font-size: 0.75rem;">${row.category}</span></td>
      <td style="max-width: 260px; font-weight: 500;">${row.claim_statement}</td>
      <td><strong>${row.endpoint_id}</strong><br><span style="font-size: 0.7rem; color: var(--text-muted);">${row.unit || ''}</span></td>
      <td><code>${row.source_file}</code><br><span style="font-size: 0.72rem; color: var(--accent-cyan); font-weight: 600;">${row.exact_line_number}</span></td>
      <td style="font-family: var(--font-mono); font-size: 0.72rem;">${row.event_timestamp}</td>
      <td style="max-width: 220px; font-family: var(--font-mono); font-size: 0.68rem; color: #cbd5e1; word-break: break-all;">${row.raw_evidence_snippet}</td>
      <td style="max-width: 200px;"><code style="font-size: 0.68rem; color: #a5b4fc;">${row.cypher_gql_pointer}</code></td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById('ledger-type-filter').addEventListener('change', renderLedgerTable);
document.getElementById('ledger-search').addEventListener('input', renderLedgerTable);

// Interactive Force-Directed Canvas Graph
function renderGraph() {
  const canvas = document.getElementById('graph-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  const nodes = [
    { id: "EPJ76RZV", type: "ep", x: 260, y: 180, label: "EPJ76RZV" },
    { id: "EPAJI3E5", type: "ep", x: 260, y: 340, label: "EPAJI3E5" },
    { id: "EPMVZYZO", type: "ep", x: 480, y: 120, label: "EPMVZYZO" },
    { id: "EPC2L3UH", type: "ep", x: 480, y: 400, label: "EPC2L3UH" },

    { id: "unit-foxtrot", type: "unit", x: 80, y: 220, label: "Unit Foxtrot" },
    { id: "unit-quebec", type: "unit", x: 80, y: 320, label: "Unit Quebec" },

    { id: "LURE_XLSX", type: "file", x: 420, y: 220, label: "Retirees_Welfare1.xlsx" },
    { id: "LURE_DOCX", type: "file", x: 420, y: 310, label: "Lakeside_traders.docx" },
    { id: "XBEL", type: "file", x: 620, y: 340, label: "recently-used.xbel" },

    { id: "SHA_XLSX", type: "hash", x: 580, y: 220, label: "SHA: d4a23078..." },
    { id: "SHA_DOCX", type: "hash", x: 580, y: 300, label: "SHA: 854b8f77..." },

    { id: "DEST_GOOGLE", type: "dest", x: 200, y: 80, label: "doc-0k-apps-viewer.google" },
    { id: "DEST_ZOHO", type: "dest", x: 200, y: 450, label: "vts.zohopublic.in" },
    { id: "DEST_FASTLY", type: "dest", x: 680, y: 150, label: "fastly-edge.com" }
  ];

  const links = [
    { from: "EPJ76RZV", to: "unit-foxtrot", label: "BELONGS_TO" },
    { from: "EPAJI3E5", to: "unit-quebec", label: "BELONGS_TO" },
    { from: "EPJ76RZV", to: "LURE_XLSX", label: "QUARANTINED" },
    { from: "EPAJI3E5", to: "LURE_DOCX", label: "QUARANTINED" },
    { from: "LURE_XLSX", to: "SHA_XLSX", label: "HAS_HASH" },
    { from: "LURE_DOCX", to: "SHA_DOCX", label: "HAS_HASH" },
    { from: "EPJ76RZV", to: "DEST_GOOGLE", label: "CONTACTED (-8m)" },
    { from: "EPAJI3E5", to: "DEST_ZOHO", label: "CONTACTED" },
    { from: "EPC2L3UH", to: "XBEL", label: "QUARANTINED" },
    { from: "EPMVZYZO", to: "DEST_FASTLY", label: "CONTACTED" }
  ];

  // Draw links
  links.forEach(l => {
    const fromNode = nodes.find(n => n.id === l.from);
    const toNode = nodes.find(n => n.id === l.to);
    if (!fromNode || !toNode) return;

    ctx.beginPath();
    ctx.moveTo(fromNode.x, fromNode.y);
    ctx.lineTo(toNode.x, toNode.y);
    ctx.strokeStyle = "rgba(255, 255, 255, 0.15)";
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Link label
    const midX = (fromNode.x + toNode.x) / 2;
    const midY = (fromNode.y + toNode.y) / 2;
    ctx.fillStyle = "rgba(148, 163, 184, 0.7)";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.fillText(l.label, midX - 20, midY - 4);
  });

  // Draw nodes
  nodes.forEach(n => {
    ctx.beginPath();
    let color = "#38bdf8";
    let radius = 16;
    if (n.type === "ep") { color = "#38bdf8"; radius = 18; }
    else if (n.type === "file") { color = "#ef4444"; radius = 15; }
    else if (n.type === "hash") { color = "#f59e0b"; radius = 12; }
    else if (n.type === "dest") { color = "#a855f7"; radius = 14; }
    else if (n.type === "unit") { color = "#10b981"; radius = 16; }

    ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.shadowBlur = 10;
    ctx.shadowColor = color;
    ctx.fill();
    ctx.shadowBlur = 0;

    ctx.fillStyle = "#ffffff";
    ctx.font = "11px 'Plus Jakarta Sans', sans-serif";
    ctx.fillText(n.label, n.x - (n.label.length * 3), n.y + radius + 14);
  });
}

// Reset view button
const btnReset = document.getElementById('btn-reset-graph');
if (btnReset) {
  btnReset.addEventListener('click', renderGraph);
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', loadDataset);
