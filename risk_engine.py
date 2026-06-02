import mysql.connector
import time
from mysql.connector import errors
def connect_to_db():
    max_retries = 5
    retry_delay = 3 # seconds
    
    print("[*] Connecting to containerized database...")
    for attempt in range(1, max_retries + 1):
        try:
            connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="EnterprisePassword2026",
                database="security_platform"
            )
            if connection.is_connected():
                print("[+] Successfully authenticated with Docker MySQL instance.")
                return connection
        except errors.InterfaceError:
            print(f"[!] Database booting up... Retry attempt {attempt}/{max_retries} in {retry_delay}s...")
            time.sleep(retry_delay)
        except errors.ProgrammingError as e:
            # Catches missing database errors if schema hasn't finished running
            print(f"[!] Database structure initializing... Retry in {retry_delay}s... ({e})")
            time.sleep(retry_delay)
            
    raise Exception("[❌] Critical Error: Could not connect to the containerized database after multiple attempts.")

def process_asset_risk_assessment():
    db = connect_to_db()
    cursor = db.cursor()
    
    print("\n[⚡] Running Enterprise Risk Engine...")
    
    cursor.execute("SELECT id, ip_address FROM assets")
    assets = cursor.fetchall()
    
    for asset in assets:
        # 1. Unpack asset tuple cleanly
        asset_id, ip = asset
        
        cursor.execute("SELECT port_number FROM open_ports WHERE asset_id = %s", [int(str(asset_id))])   
        ports = cursor.fetchall()
        
        highest_cvss = 0.0
        vulnerabilities_detected = 0
        
        print(f"\nEvaluating Asset: {ip} (ID: {asset_id})")
        
        # 2. FIX: Unpack the port directly in the loop! No more port_row[0]
        for (port_num,) in ports:
            
            cursor.execute("SELECT cve_id, cvss_score FROM cve_lookup WHERE associated_port = %s", [int(str(port_num))])
            cve_match = cursor.fetchone()
            
            if cve_match:
                vulnerabilities_detected += 1
                # 3. FIX: Unpack the CVE data directly! No more indexes
                cve_id, cvss_score = cve_match
                cvss = float(str(cvss_score))
                
                print(f"  [!] Found Match on Port {port_num}: {cve_id} (CVSS: {cvss})")
                if cvss > highest_cvss:
                    highest_cvss = cvss
                    
        # 4. Enterprise Risk Score Formula Logic
        base_risk = highest_cvss * 10
        modifier = (vulnerabilities_detected - 1) * 5 if vulnerabilities_detected > 0 else 0
        final_risk_score = min(base_risk + modifier, 100.0)
        
        print(f"  [=>] Calculated Risk Score: {final_risk_score}/100")
        
    cursor.close()
    db.close()

if __name__ == "__main__":
    process_asset_risk_assessment()