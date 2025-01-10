# Firewall Rules Simulator

A Python-based firewall rules simulator for network traffic filtering and visualization. This project enables monitoring of live network traffic, applying custom firewall rules, and logging actions for both allowed and blocked traffic. Logs are displayed interactively on a web-based dashboard.

---

## Features

- **Network Traffic Monitoring**:
  Monitor incoming and outgoing network traffic in real time.

- **Firewall Rules**:
  Define custom rules to allow or block traffic based on protocols, ports, and IP addresses.

- **Traffic Logging**:
  Log allowed and blocked traffic, including details like source IP, destination IP, protocol, and port.

- **Web-Based Dashboard**:
  View logged traffic interactively using a Flask-based dashboard.

- **Port Scanning Detection**:
  Detect malicious activities such as port scans.

---

## Technologies Used

- **Python**: Programming language for the entire project.
- **Scapy**: Packet sniffing and network monitoring.
- **Flask**: Framework for the web-based dashboard.
- **SQLite**: Database for storing traffic logs.
- **Nmap**: Simulate network traffic for testing.

---

## Installation and Setup

### Prerequisites
- Python 3.8+
- Git
- Nmap (for traffic simulation)

### Steps to Set Up the Project

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/firewall-rules-simulator.git
   cd firewall-rules-simulator
2. Set Up a Virtual Environment:

   python3 -m venv venv
   source venv/bin/activate  # For Mac/Linux

3. Install Dependencies:
   pip install scapy flask

4. Run the Firewall Script:
   sudo python3 scripts/firewall.py

5. Run the Dashboard:
   python3 dashboard/app.py

6. Access the Dashboard: Open http://127.0.0.1:5000 in your browser.

**Usage**

1. Monitor Traffic:
   The script monitors live network traffic and applies custom firewall rules.

2.Simulate Traffic:
  Use Nmap to simulate traffic for testing:
    sudo nmap -sS localhost

3. View Logs:
   Access the dashboard to view logs of allowed and blocked traffic.

**Customization**

1. Add or Modify Firewall Rules:
   Edit the firewall_rules list in scripts/firewall.py to define new rules:
     firewall_rules = [
    {"protocol": "TCP", "port": 80, "action": "ALLOW"},  # Allow HTTP
    {"protocol": "TCP", "port": 443, "action": "ALLOW"}, # Allow HTTPS
    {"protocol": "TCP", "port": 22, "action": "BLOCK"},  # Block SSH
]

2. Extend Logging:
   Modify the database schema or add new fields to log more details.

**Contributing**
Contributions are welcome! Feel free to open issues or submit pull requests to improve the project.

**License**
This project is licensed under the MIT License - see the LICENSE file for details.

**Contact**
For questions or feedback, reach out to:

Name: Utkarsh Navadiya
Email: info@utkarshnavadia.com
