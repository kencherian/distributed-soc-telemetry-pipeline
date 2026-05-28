import socket

def scan_target(ip_address):
    # The common doors (ports) we want to check
    ports_to_scan = [22, 80, 443, 8080]
    
    print(f"\n--- Starting Scan on Target: {ip_address} ---")
    
    found_ports = []
    
    for port in ports_to_scan:
        # Create a socket network connection object
        # AF_INET = IPv4, SOCK_STREAM = TCP connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout so it doesn't freeze forever if a port is closed (1 second)
        s.settimeout(1.0)
        
        # Try to connect to the IP and Port
        result = s.connect_ex((ip_address, port))
        
        # connect_ex returns 0 if the connection was successful
        if result == 0:
            print(f"[+] Port {port}: OPEN")
            found_ports.append(port)
        else:
            print(f"[-] Port {port}: CLOSED")
            
        # Always close the network socket
        s.close()
        
    return found_ports

if __name__ == "__main__":
    # Test it on a public, safe-to-scan DNS server (Cloudflare DNS)
    # or you can use '127.0.0.1' if you have your Apache server running
    target = "1.1.1.1" 
    open_ports = scan_target(target)
    print(f"\nScan complete. Found open ports: {open_ports}")