# Anomaly Detection on Nmap Scan Results using Isolation Forest

## Overview
This project explores anomaly detection techniques for network scan data
by analyzing large-scale **nmap XML scan results**.

To ensure privacy and ethical compliance, the project does not use real network data.
Instead, it generates **synthetic but realistic nmap scan outputs**, then applies
statistical and machine-learning-based approaches to identify suspicious port behavior.

The current implementation focuses on a **frequency-based anomaly detection baseline**,
designed as a transparent and explainable precursor to Isolation Forest–based modeling.

---

## Objectives
- Parse and flatten nmap XML scan outputs
- Design meaningful features from port/service information
- Detect anomalous port behavior without labeled data
- Demonstrate privacy-aware security data handling suitable for public portfolios
- Establish a baseline method prior to applying Isolation Forest

---

## Technologies
- Python
- nmap (XML output format)
- pandas
- scikit-learn (planned / Isolation Forest)
- XML parsing

---

## Repository Structure
```
├─ generate_xml.py # Generate synthetic nmap scan results (XML)
├─ nmap_scan_test.xml # Synthetic scan data (privacy-safe)
├─ nmap_analyze4.py # Frequency-based anomaly detection baseline
├─ result.txt # Detected anomaly candidates
└─ README.md　　
```

---

## Workflow
1. **Synthetic Data Generation**
   - `generate_xml.py` creates nmap-compatible XML data
   - Normal traffic patterns and a small number of injected anomalies are included
   - Private IP ranges are used to avoid any real-world exposure

2. **XML Parsing & Feature Extraction**
   - Each port entry is flattened into a tabular format:
     - IP address
     - Port number
     - Protocol
     - State
     - Service name
   - A combined `Signature` feature (`port/service`) is created

3. **Baseline Anomaly Detection (Frequency Analysis)**
   - Occurrence frequency of each `Signature` is calculated
   - Rare signatures (appearing in less than 1% of total entries) are flagged as anomalies
   - Results are written to `result.txt` for inspection

4. **Validation**
   - Intentionally injected anomalies (e.g. `80/mysql`, `65123/unusual-svc`)
     are successfully detected by the baseline method

---

## Baseline Detection Rationale
Before applying Isolation Forest, a frequency-based approach is implemented to:

- Provide a fully explainable anomaly detection baseline
- Validate feature design and data quality
- Reflect real-world security analysis, where rare port/service combinations
  often indicate misconfiguration or suspicious activity

This approach also highlights the **class imbalance problem** common in
network security data.

---

## Example Detected Anomalies
Examples of signatures flagged as anomalous include:

- `21/http-proxy` (unexpected service on FTP port)
- `80/mysql` (service/port mismatch)
- `5555/unknown` (uncommon open port)
- `65123/unusual-svc` (rare high-numbered port)
- `111/rpcbind` in filtered state

These align with the anomalies intentionally injected during data generation.

---

## Future Work
- Replace or augment the frequency-based baseline with Isolation Forest
- Add feature encoding for categorical variables
- Compare statistical vs. ML-based detection results
- Visualize anomaly score distributions

---

## Disclaimer
All scan data included in this repository is synthetically generated.

It does not represent any real network, host, or system.

