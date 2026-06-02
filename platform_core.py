import socket
import mysql.connector

def connect_to_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="EnterprisePassword2026", 
        database="security_platform"
    )

def scan_target(ip_address):
    ports_to_scan = [22, 80, 443, 8080]
    open_ports = []
    print(f"\n[!] Scanning {ip_address}...")
    
    for port in ports_to_scan:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((ip_address, port))
        if result == 0:
            print(f"   [+] Found Open Port: {port}")
            open_ports.append(port)
        s.close()
    return open_ports

def save_results_to_database(ip, open_ports):
    db = connect_to_db()
    cursor = db.cursor()
    
    try:
        # 1. Insert the asset or update it if it already exists
        add_asset_query = "INSERT INTO assets (ip_address, hostname) VALUES (%s, %s)"
        cursor.execute(add_asset_query, (ip, "Cloudflare-Target"))
        
        # Get the unique ID of the asset we just inserted
        asset_id = cursor.lastrowid
        
        # 2. Insert each open port found into the open_ports table
        if open_ports:
            add_port_query = "INSERT INTO open_ports (asset_id, port_number) VALUES (%s, %s)"
            for port in open_ports:
                cursor.execute(add_port_query, (asset_id, port))
        
        # Commit the changes to the database
        db.commit()
        print(f"\n[✅] Success: Saved asset ID {asset_id} with {len(open_ports)} open ports to database.")
        
    except mysql.connector.Error as err:
        print(f"[❌] Database Error: {err}")
    finally:
        cursor.close()
        db.close()

if __name__ == "__main__":
    target_ip = "1.1.1.1"
    
    # Run the scanner
    found_ports = scan_target(target_ip)
    
    # Save the results
    save_results_to_database(target_ip, found_ports)