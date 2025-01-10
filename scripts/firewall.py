from scapy.all import sniff, IP, TCP, UDP
import sqlite3
from datetime import datetime

# Define firewall rules (examples)
firewall_rules = [
    {"protocol": "TCP", "port": 80, "action": "ALLOW"},  # Allow HTTP
    {"protocol": "TCP", "port": 443, "action": "ALLOW"}, # Allow HTTPS
    {"protocol": "TCP", "port": 22, "action": "BLOCK"},  # Block SSH
]

# Log actions to the database
def log_to_db(src_ip, dest_ip, protocol, port, action):
    conn = sqlite3.connect('../logs/firewall_logs.db')
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS logs (
                        timestamp TEXT,
                        src_ip TEXT,
                        dest_ip TEXT,
                        protocol TEXT,
                        port INTEGER,
                        action TEXT)""")
    cursor.execute("INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?)", 
                   (datetime.now(), src_ip, dest_ip, protocol, port, action))
    conn.commit()
    conn.close()

# Check if a packet matches any firewall rule
def apply_firewall_rules(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet[IP].proto
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            for rule in firewall_rules:
                if rule["protocol"] == "TCP" and packet.haslayer(TCP) and rule["port"] == port:
                    log_to_db(src_ip, dest_ip, "TCP", port, rule["action"])
                    return rule["action"] == "ALLOW"
                if rule["protocol"] == "UDP" and packet.haslayer(UDP) and rule["port"] == port:
                    log_to_db(src_ip, dest_ip, "UDP", port, rule["action"])
                    return rule["action"] == "ALLOW"
    return True  # Allow if no rule matches

# Packet callback function
def packet_callback(packet):
    if not apply_firewall_rules(packet):
        print(f"Blocked: {packet.summary()}")
    else:
        print(f"Allowed: {packet.summary()}")

# Start monitoring traffic
def monitor_traffic():
    print("Monitoring traffic...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    monitor_traffic()
