# Enterprise Asset Visibility & Compliance Platform 🛡️

A full-stack, automated security engineering tool that performs active network reconnaissance, cross-references discovered network infrastructure states against structured CVE threat intelligence, and calculates real-time asset risk metrics on a centralized management dashboard.

## 🏗️ Architecture & Flow

The platform operates across a synchronized decoupled engine architecture:
1. **Reconnaissance Engine (Python):** Connects via low-level sockets to probe internal asset networks for operational services.
2. **Relational Database Layer (MySQL):** Aggregates asset telemetry data, mapping multiple active port identifiers back to a unified asset profile.
3. **Risk Prioritization Engine (Python):** Evaluates asset risk metrics based on threat signatures, applying a custom business-logic weighting model based on absolute CVSS metrics.
4. **Analyst Dashboard (PHP/LAMP Stack):** Renders a responsive UI highlighting non-compliant network endpoints and tracking threat classifications.

## ⚡ Technical Core Features
* **Relational Asset Inventory Integration:** Normalizes target IPs and maps network properties across structured MySQL schemas.
* **Algorithmic Threat Modeling:** Implements a dynamic prioritization system factoring in multiple exploit exposures to cap asset risk scores (0–100%).
* **Type-Safe Python Execution:** Engineered with strict tuple-unpacking methodologies to ensure stable backend runtime execution.
* **Executive-Grade Reporting Interface:** Clean Bootstrap-based console for visibility into enterprise compliance postures.

---

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.x
* Local LAMP stack installation (XAMPP / WampServer / Local Apache/MySQL)
* Python MySQL connector (`pip install mysql-connector-python`)

### 1. Database Provisioning
Import the database schema using your local administrative tool (e.g., phpMyAdmin):

```sql
CREATE DATABASE security_platform;
USE security_platform;

CREATE TABLE assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    hostname VARCHAR(255) DEFAULT 'Unknown',
    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE open_ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT,
    port_number INT NOT NULL,
    status VARCHAR(20) DEFAULT 'Open',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE cve_lookup (
    id INT AUTO_INCREMENT PRIMARY KEY,
    associated_port INT UNIQUE,
    cve_id VARCHAR(50),
    cvss_score DECIMAL(3,1),
    severity VARCHAR(20),
    description TEXT
);

INSERT INTO cve_lookup (associated_port, cve_id, cvss_score, severity, description) VALUES
(80, 'CVE-2023-4567', 7.5, 'High', 'Apache HTTP Server Outdated Version - Remote Code Execution'),
(8080, 'CVE-2024-1234', 9.8, 'Critical', 'Unauthenticated Remote Command Injection in Web UI'),
(22, 'CVE-2022-3839', 5.3, 'Medium', 'OpenSSH Information Disclosure via Timing Side-Channel');
2. Backend Orchestration Execution
Run the asset discovery utility to populate active endpoints:

Bash
python platform_core.py
Process calculated metrics via the centralized engine:

Bash
python risk_engine.py
3. Web UI Deployment
Deploy the interface files within your active web root engine directory (e.g., /xampp/htdocs/security_dashboard/index.php).

Navigate your server gateway client browser instance to:

Plaintext
http://localhost/security_dashboard/index.php

---

## 🚀 Step-by-Step GitHub Upload Instructions

Let's push this live directly from your Cursor terminal. Run these commands line-by-line:

### 1. Initialize your repository locally
```bash
git init
2. Add a .gitignore file so you don't push temporary system files
Run this command in the terminal to create a .gitignore:

Bash
echo "__pycache__/\n*.pyc" > .gitignore
3. Stage and commit your project assets
Bash
git add .
git commit -m "Feat: Complete core implementation of Enterprise Asset Visibility Platform"