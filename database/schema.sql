CREATE DATABASE IF NOT EXISTS security_platform;
USE security_platform;

CREATE TABLE IF NOT EXISTS assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    hostname VARCHAR(255) DEFAULT 'Unknown',
    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS open_ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT,
    port_number INT NOT NULL,
    status VARCHAR(20) DEFAULT 'Open',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_lookup (
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
(22, 'CVE-2022-3839', 5.3, 'Medium', 'OpenSSH Information Disclosure via Timing Side-Channel')
ON DUPLICATE KEY UPDATE cve_id=cve_id;