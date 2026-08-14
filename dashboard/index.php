<?php
$host = "threat-db";
$username = "root";
$password = "EnterprisePassword2026";
$dbname = "security_platform";

$max_retries = 3;
$retry_delay = 2;
$conn = null;

for ($attempt = 1; $attempt <= $max_retries; $attempt++) {
    try {
        $conn = @new mysqli($host, $username, $password, $dbname);
        if (!$conn->connect_error) { break; }
    } catch (Exception $e) {}
    if ($attempt < $max_retries) { sleep($retry_delay); }
}

if (!$conn || $conn->connect_error) {
    die("<div class='alert alert-danger m-5'><strong>🚨 SIEM Database Connection Failure</strong></div>");
}

// Query 1: Assets Registry file
$asset_sql = "SELECT a.id, a.ip_address, a.hostname, a.last_scanned, 
                     GROUP_CONCAT(DISTINCT o.port_number SEPARATOR ', ') as open_ports,
                     COUNT(DISTINCT c.cve_id) as exposure_count,
                     MAX(c.cvss_score) as max_cvss
              FROM assets a
              LEFT JOIN open_ports o ON a.id = o.asset_id
              LEFT JOIN cve_lookup c ON o.port_number = c.associated_port
              GROUP BY a.id ORDER BY a.last_scanned DESC";
$asset_result = $conn->query($asset_sql);

// Query 2: Live Incident Timeline
$incident_sql = "SELECT id, rule_name, severity, file_target, timestamp 
                 FROM security_incidents ORDER BY timestamp DESC LIMIT 5";
$incident_result = $conn->query($incident_sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Security Telemetry & SIEM Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-white p-5">
    <div class="container">
        <header class="pb-3 mb-4 border-bottom d-flex justify-content-between align-items-center">
            <span class="fs-4 text-info">🛡️ Distributed Threat Telemetry SIEM Console</span>
            <span class="badge bg-danger p-2">🔴 ENGINE ONLINE</span>
        </header>

        <h3 class="my-4 text-light">Network Asset Risk Matrix</h3>
        <table class="table table-dark table-striped border border-secondary text-center align-middle mb-5">
            <thead>
                <tr>
                    <th>Asset ID</th><th>Target</th><th>Risk Score</th><th>Threat Exposure</th><th>Active Ports</th><th>Compliance</th>
                </tr>
            </thead>
            <tbody>
                <?php
                if ($asset_result->num_rows > 0) {
                    while($row = $asset_result->fetch_assoc()) {
                        $highest_cvss = isset($row['max_cvss']) ? floatval($row['max_cvss']) : 0.0;
                        $exposures = intval($row['exposure_count']);
                        $final_risk = min(($highest_cvss * 10) + (($exposures - 1) * 5), 100.0);
                        if ($exposures == 0) $final_risk = 0;

                        $badge = $final_risk >= 75 ? "bg-danger text-white" : ($final_risk >= 40 ? "bg-warning text-dark" : "bg-success text-white");
                        $status = $final_risk >= 75 ? "❌ CRITICAL THREAT" : ($final_risk >= 40 ? "⚠️ VULNERABLE" : "✅ COMPLIANT");

                        echo "<tr>
                                <td>".$row["id"]."</td>
                                <td><strong>".$row["ip_address"]."</strong><br><small class='text-muted'>".$row["hostname"]."</small></td>
                                <td><span class='badge ".$badge." p-2'>".$final_risk." / 100</span></td>
                                <td><span class='text-warning'>".$exposures." Active CVEs</span></td>
                                <td><span class='badge bg-secondary p-2'>".($row["open_ports"] ? $row["open_ports"] : "Secure")."</span></td>
                                <td><strong>".$status."</strong></td>
                              </tr>";
                    }
                } else { echo "<tr><td colspan='6' class='text-warning'>No scanned infrastructure logged.</td></tr>"; }
                ?>
            </tbody>
        </table>

        <h3 class="my-4 text-danger">🚨 Live EDR / Detection Rule Alerts</h3>
        <table class="table table-dark table-hover border border-danger align-middle">
            <thead class="table-danger">
                <tr class="text-center">
                    <th>Alert ID</th><th>Detection Rule</th><th>Severity</th><th>File Target Path</th><th>Detection Timestamp</th>
                </tr>
            </thead>
            <tbody>
                <?php
                if ($incident_result->num_rows > 0) {
                    while($row = $incident_result->fetch_assoc()) {
                        echo "<tr class='border-bottom border-secondary text-center'>
                                <td>".$row["id"]."</td>
                                <td class='text-start text-danger fw-bold'>💥 ".$row["rule_name"]."</td>
                                <td><span class='badge bg-danger px-3 py-1'>".$row["severity"]."</span></td>
                                <td class='text-start'><code>".$row["file_target"]."</code></td>
                                <td><small class='text-muted'>".$row["timestamp"]."</small></td>
                              </tr>";
                    }
                } else { echo "<tr><td colspan='5' class='text-warning text-center'>No active signature violations tripped.</td></tr>"; }
                ?>
            </tbody>
        </table>
    </div>
</body>
</html>
<?php $conn->close(); ?>
