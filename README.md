# PS-005: BGP Hijack & Route Leak Detection System
### Real-Time RPKI Validation + ML-Enhanced Anomaly Detection
**Team Code:** A3-PS005-TC548 | **Team Name:** PRISM | **Institution:** IIT Guwahati

---

## 🎥 Proposal Video
https://drive.google.com/file/d/19TNxLkUiojN4duOh7i48hMnbpKdVXVgU/view?usp=sharing

---

## 📌 Problem Description
**BGP (Border Gateway Protocol)** serves as the routing backbone of the global internet but inherently lacks built-in security mechanisms. Malicious or misconfigured networks can falsely announce IP prefixes (**BGP Hijacking**), rerouting massive internet traffic chunks for data interception, surveillance, or financial theft. 

### Key Project Motivations
* **Real-World Violations:** Incidents like the 2010 China Telecom leak and the 2018 Amazon Route 53 hijack highlight the critical vulnerabilities of BGP trust assumptions.
* **Detection Pipeline Gap:** Existing tooling alerts operators but lacks integrated, multi-layered RPKI validation alongside automated machine learning anomaly checks.
* **Regional Focus:** Provides a lightweight, open-source tool built explicitly for Indian network operators managing large Autonomous System Number (ASN) portfolios (e.g., Airtel, Jio, BSNL).

---

## ⚙️ Architecture & Data Ingestion Pipeline
The framework parses multi-threaded routing toolkit binary streams into an active detection system using three primary validation layers:

1. **BGP Ingestion Engine:** Utilizes `mrtparse` to continuously ingest TABLE_DUMP_V2 and UPDATE messages, extracting prefix, origin ASN, and the full AS_PATH.
2. **RPKI Validation Layer:** Evaluates live prefix records against a bucket-indexed database of **1,018,636 ROAs (Route Origin Authorizations)** derived from the Cloudflare RPKI API.
3. **Priority Rule-Based Filter:** Evaluates routing updates across four strict severities to completely prevent double-alerting or misclassifications:
   \[\text{SUBPREFIX\_HIJACK} \longrightarrow \text{ORIGIN\_MISMATCH} \longrightarrow \text{UNKNOWN\_PREFIX} \longrightarrow \text{ROUTE\_LEAK}\]

---

## 📈 System Optimizations

| Component | Naïve Inefficient Approach | Our Engineered Optimization |
| :--- | :--- | :--- |
| **ROA Lookup Speed** | Linear scan over 1M+ ROAs (O(n) per lookup) taking minutes per dump. | **Bucket index keyed on /8 IPv4 & /32 IPv6** (O(1) lookup processing 200 events in ~3s). |
| **Alert Priority** | Checking origin mismatch first leads to sub-prefix hijack misclassification. | **Sub-prefix checked first**, isolating high-risk longer matches before origin logic triggers. |
| **Imbalanced Class Data** | Standard models bias heavily toward legitimate routes, missing rare hijacks. | Implements **`class_weight='balanced'` in Random Forest** combined with unsupervised Isolation Forest. |
| **Zero-Day Blindspots** | Static rules completely miss threat profiles without pre-configured definitions. | **Isolation Forest** tracks structural vector data to isolate novel anomalies without training labels. |

---

## 📊 Evaluation & Machine Learning Metrics
Evaluated on **200 synthetic hijack events** (50 origin mismatches, 50 sub-prefixes, 50 unknown prefixes, 50 route leaks) executed against a 1-million record baseline:

* **Precision:** `0.855`
* **Recall:** `1.000` (Caught 100% of injected hijack variants)
* **F1-Score:** `0.922`
* **Pipeline Speed:** Execution pipeline updates evaluate in **~3 seconds**.

---

## 🗺️ Project Roadmap & Deployment Timeline

### 🗓️ Phase 1: Completed Foundations (Sept - Oct 2026)
* **Week 1-2:** Integrated `mrtparse` ingestion, built the /8 and /32 structural lookup indices, and configured core rule exceptions.
* **Week 3:** Completed the 4-rule prioritized engine, integrated the synthetic event injector, and verified rule accuracy.
* **Week 4:** Integrated the 8-feature machine learning vectors, balanced the Random Forest estimators, and ran the end-to-end evaluation.

### 🗓️ Phase 2: Proposed Level 2 Implementation (Proposed Work)
* **Milestone 1: Live Stream Ingestion:** Shift from static MRT archive dumps to continuous WebSocket feeds via the **RIPE RIS Live API**.
* **Milestone 2: Sub-Second Stream ML:** Adapt feature extraction methods to calculate streaming AS_PATH variations and state deviations live.
* **Milestone 3: Visual Dashboard & Dockerization:** Launch an interactive, containerized operator console displaying active ASN tracking alerts categorized by target threat levels.

---

## 📁 Repository Structure
```text
├── src/
│   ├── bgp_parser.py   # Decompresses & extracts (prefix, origin_asn, as_path) from MRT streams
│   ├── roa_loader.py   # Handles O(1) bucket indices for Cloudflare RPKI JSON dumps
│   ├── detector.py     # Executes the prioritized 4-stage validation rules
│   ├── ml_model.py     # Houses Random Forest & Isolation Forest feature processing
│   └── evaluator.py    # Generates system confusion matrices and validation metrics
├── reports/
│   ├── alerts.json     # Live structured system alert output log
│   ├── metrics.json    # Precision, recall, and overall performance outputs
│   └── ml_report.txt   # Detailed machine learning classification summaries
└── fetch_and_run.py    # Main orchestration pipeline driver script
```

---

## 👨‍💻 Team PRISM & Project Details
* **Lead Researchers:** Pavan Sri Sai Pendurthi & Dar Jasif
* **Project Lab:** PRISM Lab, Indian Institute of Technology (IIT), Guwahati
* **Research Supervisor:** Dr. Satyajit Das
* **GitHub Repository:** [PavanPendurthi/A3-PS005-TC548](https://github.com/PavanPendurthi/A3-PS005-TC548)
