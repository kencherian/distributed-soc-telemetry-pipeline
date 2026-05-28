<?php
// 1. Establish database connection
$host = "localhost";
$username = "root";
$password = "";
$dbname = "security_platform";

$conn = new mysqli($host, $username, $password, $dbname);

if ($conn->connect_error) {
    die("<div class='alert alert-danger'>Connection failed: " . $conn->connect_error . "</div>");
}

// 2. Complex Enterprise Query: Join assets, calculate highest CVSS, and find active exposures
$sql = "SELECT a.id, a.ip_address, a.hostname, a.last_scanned, 
               GROUP_CONCAT(DISTINCT o.port_number SEPARATOR ', ') as open_ports,
               COUNT(DISTINCT c.cve_id) as exposure_count,
               MAX(c.cvss_score) as max_cvss
        FROM assets a
        LEFT JOIN open_ports o ON a.id = o.asset_id
        LEFT JOIN cve_lookup c ON o.port_number = c.associated_port
        GROUP BY a.id 
        ORDER BY a.last_scanned DESC";

$result = $conn->query($sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Asset Visibility Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-white p-5">

    <div class="container">
        <header class="pb-3 mb-4 border-bottom d-flex justify-content-between align-items-center">
            <span class="fs-4 text-info">🛡️ Enterprise Asset Visibility & Compliance Platform</span>
            <span class="badge bg-primary p-2">v1.2 Live Engine</span>
        </header>

        <div class="p-4 mb-4 bg-secondary rounded-3">
            <h1 class="display-6 fw-bold">Risk Prioritization Console</h1>
            <p class="text-warning">Real-time mapping of network infrastructure to active CVE Databases & Threat Intelligence.</p>
        </div>

        <h3 class="my-4 text-light">Asset Risk Registry</h3>
        
        <table class="table table-dark table-striped table-hover border border-secondary text-center align-middle">
            <thead>
                <tr>
                    <th>Asset ID</th>
                    <th>Network Target</th>
                    <th>Risk Score</th>
                    <th>OWASP / CVE Exposure</th>
                    <th>Active Ports</th>
                    <th>Compliance Status</th>
                </tr>
            </thead>
            <tbody>
                <?php
                if ($result->num_rows > 0) {
                    while($row = $result->fetch_assoc()) {
                        // Reproduce our Python Risk Logic right on the frontend dashboard!
                        $highest_cvss = isset($row['max_cvss']) ? floatval($row['max_cvss']) : 0.0;
                        $exposures = intval($row['exposure_count']);
                        
                        $base_risk = $highest_cvss * 10;
                        $modifier = ($exposures - 1) * 5;
                        if ($exposures == 0) { $modifier = 0; }
                        
                        $final_risk_score = min($base_risk + $modifier, 100.0);
                        
                        // Select color badge based on risk level
                        if ($final_risk_score >= 75) {
                            $badge_color = "bg-danger text-white";
                            $status = "❌ CRITICAL THREAT";
                        } elseif ($final_risk_score >= 40) {
                            $badge_color = "bg-warning text-dark";
                            $status = "⚠️ VULNERABLE";
                        } else {
                            $badge_color = "bg-success text-white";
                            $status = "✅ COMPLIANT";
                        }

                        echo "<tr>";
                        echo "<td>" . $row["id"] . "</td>";
                        echo "<td><strong>" . $row["ip_address"] . "</strong><br><small class='text-muted'>" . $row["hostname"] . "</small></td>";
                        echo "<td><span class='badge " . $badge_color . " p-2 fs-6'>" . $final_risk_score . " / 100</span></td>";
                        echo "<td><span class='text-warning'>" . $exposures . " Active CVEs Blown</span></td>";
                        
                        // Ports Badge
                        $ports_list = $row["open_ports"];
                        if ($ports_list) {
                            echo "<td><span class='badge bg-secondary p-2'>" . $ports_list . "</span></td>";
                        } else {
                            echo "<td><span class='badge bg-success p-2'>Secure</span></td>";
                        }
                        
                        echo "<td><strong>" . $status . "</strong></td>";
                        echo "</tr>";
                    }
                } else {
                    echo "<tr><td colspan='6' class='text-warning text-center'>No assets monitored.</td></tr>";
                }
                ?>
            </tbody>
        </table>
    </div>

</body>
</html>
<?php $conn->close(); ?>