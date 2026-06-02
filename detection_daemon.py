import yara
import os
import mysql.connector

def connect_to_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="EnterprisePassword2026", # Your Docker DB Password
        database="security_platform"
    )

def log_incident_to_db(rule_name, severity, file_path):
    try:
        db = connect_to_db()
        cursor = db.cursor()
        
        sql = "INSERT INTO security_incidents (rule_name, severity, file_target) VALUES (%s, %s, %s)"
        cursor.execute(sql, (rule_name, severity, file_path))
        
        db.commit()
        print(f"    [💾] Incident logged to central SIEM database successfully.")
        cursor.close()
        db.close()
    except Exception as e:
        print(f"    [❌] Failed to log incident to database: {e}")

def run_signature_detection(directory_to_scan):
    print("\n[🔍] Initializing YARA Detection Engine...")
    
    rule_path = "rules/malware_signatures.yar"
    if not os.path.exists(rule_path):
        print(f"[❌] Error: Rule file not found at {rule_path}")
        return

    rules = yara.compile(filepath=rule_path)
    print(f"[*] Scanning directory: {directory_to_scan} for malicious exploit strings...")

    for root, dirs, files in os.walk(directory_to_scan):
        for filename in files:
            file_path = os.path.join(root, filename)
            
            try:
                matches = rules.match(file_path)
                if matches:
                    print(f"  [🚨] ALERT: Malicious Signature Detected in {file_path}!")
                    for match in matches:
                        print(f"      Matched Rule: {match.rule} | Severity: Critical")
                        # AUTOMATED PIPELINE ACTION: Log it!
                        log_incident_to_db(match.rule, "Critical", file_path)
                else:
                    print(f"  [✅] File Clean: {filename}")
            except Exception as e:
                print(f"Error scanning {filename}: {e}")

if __name__ == "__main__":
    run_signature_detection("uploaded_payloads")