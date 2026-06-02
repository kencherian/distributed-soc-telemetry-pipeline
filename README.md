# Distributed-SOC-Telemetry-Pipeline 🛡️

A containerized, full-stack security engineering architecture designed to perform automated active network reconnaissance, cross-reference infrastructure states against dynamic CVE data models, execute real-time YARA-driven endpoint intrusion detections, and aggregate security metrics onto a centralized SIEM Operations Dashboard.

---

## 🏗️ System Architecture & Data Pipeline Flow

The platform utilizes a decoupled microservices design orchestrated natively within an isolated containerized infrastructure:

1. **Reconnaissance Engine (Python Backend):** Leverages low-level network socket structures to audit endpoint vulnerability target environments.
2. **Relational Database Cluster (Containerized MySQL):** Normalizes asset fingerprints and registers identified open ports using a strict one-to-many schema mapping.
3. **Detection & Signature Daemon (YARA / Python):** Performs active file-system integrity checks against custom rule matrices, trapping active Indicators of Compromise (IoCs) like web shell backdoor code.
4. **Centralized Management Console (PHP/Apache Container):** Collects processed threat streams to render real-time asset risk metrics and cryptographic intrusion feeds.

---

## ⚡ Technical Core Competencies & Capabilities

* **Microservices Containerization:** Orchestrated across a private bridge network using **Docker** and **Docker Compose**, stripping host-dependency vulnerabilities and eliminating local environment port conflicts.
* **Algorithmic Risk Prioritization Engine:** Evaluates dynamic asset hazard factors (0–100%) by correlating maximum CVSS severity metrics with mathematical modifiers tracking secondary exploit exposures.
* **Resilient Infrastructure Design:** Implements high-durability database connection retry mechanisms across backend engines and application logic to gracefully handle service initialization race conditions.
* **Automated SOC Incident Tracking:** Incorporates real-time structural logging pipelines that map YARA-triggered execution alerts directly into a centralized schema tracking file target paths and signatures.

---

## 🛠️ Local Deployment & Infrastructure Setup

### Prerequisites
* Docker & Docker Desktop Installed and Engine running
* Python 3.x with Virtual Environment (`venv`) provisioned

### 1. Initialize Containerized Ecosystem
Bring up the entire microservices stack (MySQL Database cluster and the Apache PHP frontend application console) in detached mode from your project root:
```bash
docker compose up -d
Note: This automatically initializes the schema definitions and injects baseline CVE signature threat intelligence inside the isolated data volume.

2. Populate Assets via Network Telemetry Core
Activate your virtual environment, verify package configurations, and execute the core discovery scanner to log remote asset variables:

Bash
python platform_core.py
3. Run the Risk Prioritization Engine
Process raw relational asset logs through the calculation engine to map enterprise threat matrices:

Bash
python risk_engine.py
4. Execute the Continuous Detection Daemon
Deploy the automated YARA monitor to parse internal staging scopes and stream signature alerts upon detecting active backdoor files:

Bash
python detection_daemon.py
5. Access the Analyst Dashboard UI
Open your browser interface and navigate to the mapped web server gateway:

Plaintext
http://localhost:8081/index.php
📜 Active Threat Detection Rule Sample (YARA)
The engine evaluates live directory footprints utilizing targeted rule files to capture post-exploit persistence vectors:

Code snippet
rule Web_Shell_Exploit {
    meta:
        description = "Detects basic web shell payload injections on open HTTP ports"
        severity = "Critical"
    strings:
        $php_shell = "exec($_POST["
        $cmd_shell = "system($_GET["
    condition:
        any of them
}