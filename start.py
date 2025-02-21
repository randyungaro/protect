import socket
import os
import re
import subprocess
import hashlib
from datetime import datetime
import nmap
import requests
import time
import sys
from threading import Thread
from queue import Queue
import logging

class BlueTeamToolkit:
    def __init__(self):
        self.scan_results = {}
        self.log_file = "blue_team_log.txt"
        logging.basicConfig(filename=self.log_file, level=logging.INFO,
                          format='%(asctime)s - %(levelname)s - %(message)s')

    def port_scanner(self, target, ports):
        """Scan specified ports on target host"""
        print(f"\nScanning {target}...")
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    print(f"Port {port}: Open")
                    self.scan_results[port] = "Open"
                sock.close()
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
        logging.info(f"Port scan completed on {target}")

    def network_discovery(self, ip_range):
        """Discover active hosts in network"""
        nm = nmap.PortScanner()
        print(f"\nDiscovering network {ip_range}...")
        nm.scan(hosts=ip_range, arguments='-sn')
        for host in nm.all_hosts():
            print(f"Host found: {host} ({nm[host].hostname()})")
        logging.info(f"Network discovery completed for {ip_range}")
        return nm.all_hosts()

    def check_password_strength(self, password):
        """Analyze password strength"""
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password too short")
            
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r"[0-9]", password):
            score += 1
        else:
            feedback.append("Add numbers")
            
        if re.search(r"[!@#$%^&*]", password):
            score += 1
        else:
            feedback.append("Add special characters")
            
        print(f"\nPassword Strength Score: {score}/6")
        if feedback:
            print("Suggestions:", ", ".join(feedback))
        logging.info(f"Password strength check performed")

    def analyze_logs(self, log_file):
        """Basic log file analysis"""
        suspicious_patterns = [r'failed login', r'error', r'unauthorized', r'access denied']
        findings = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    for pattern in suspicious_patterns:
                        if re.search(pattern, line.lower()):
                            findings.append(line.strip())
            print(f"\nFound {len(findings)} suspicious entries")
            for finding in findings[:5]:  # Show first 5
                print(finding)
            logging.info(f"Log analysis completed on {log_file}")
        except Exception as e:
            print(f"Error analyzing logs: {e}")

    def hash_file(self, file_path):
        """Generate file hashes"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                md5 = hashlib.md5(content).hexdigest()
                sha256 = hashlib.sha256(content).hexdigest()
            print(f"\nMD5: {md5}")
            print(f"SHA256: {sha256}")
            logging.info(f"File hashed: {file_path}")
        except Exception as e:
            print(f"Error hashing file: {e}")

    def check_vulnerability(self, cve_id):
        """Check CVE details from NVD"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                desc = data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
                print(f"\nCVE Details for {cve_id}:")
                print(desc)
            logging.info(f"CVE lookup performed: {cve_id}")
        except Exception as e:
            print(f"Error fetching CVE data: {e}")

    def monitor_network(self, duration):
        """Monitor network traffic (simple packet counter)"""
        print(f"\nMonitoring network for {duration} seconds...")
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.recvfrom(65565)
                packet_count += 1
            except:
                continue
        print(f"Detected {packet_count} packets")
        logging.info(f"Network monitored for {duration} seconds")

    def check_open_ports_fast(self, target):
        """Quick port scan using threading"""
        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"Port {port}: Open")
            sock.close()

        threads = []
        for port in range(1, 1001):  # Scan first 1000 ports
            t = Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
        logging.info(f"Fast port scan completed on {target}")

    def generate_security_report(self):
        """Generate a security report"""
        report = f"Blue Team Security Report - {datetime.now()}\n"
        report += "=" * 50 + "\n"
        report += f"Scan Results: {len(self.scan_results)} ports scanned\n"
        report += "Open Ports:\n"
        for port, status in self.scan_results.items():
            report += f"Port {port}: {status}\n"
            
        with open("security_report.txt", "w") as f:
            f.write(report)
        print("\nSecurity report generated: security_report.txt")
        logging.info("Security report generated")

    def menu(self):
        """Display menu and handle user input"""
        while True:
            print("\n=== Blue Team Security Toolkit ===")
            print("1. Port Scanner")
            print("2. Network Discovery")
            print("3. Password Strength Checker")
            print("4. Log Analyzer")
            print("5. File Hash Generator")
            print("6. CVE Lookup")
            print("7. Network Monitor")
            print("8. Fast Port Scanner")
            print("9. Generate Security Report")
            print("10. Exit")
            
            choice = input("Enter choice (1-10): ")
            
            if choice == "1":
                target = input("Enter target IP: ")
                ports = [int(p) for p in input("Enter ports (comma-separated): ").split(",")]
                self.port_scanner(target, ports)
                
            elif choice == "2":
                ip_range = input("Enter IP range (e.g., 192.168.1.0/24): ")
                self.network_discovery(ip_range)
                
            elif choice == "3":
                password = input("Enter password to check: ")
                self.check_password_strength(password)
                
            elif choice == "4":
                log_file = input("Enter log file path: ")
                self.analyze_logs(log_file)
                
            elif choice == "5":
                file_path = input("Enter file path: ")
                self.hash_file(file_path)
                
            elif choice == "6":
                cve_id = input("Enter CVE ID (e.g., CVE-2023-1234): ")
                self.check_vulnerability(cve_id)
                
            elif choice == "7":
                duration = int(input("Enter monitoring duration (seconds): "))
                self.monitor_network(duration)
                
            elif choice == "8":
                target = input("Enter target IP: ")
                self.check_open_ports_fast(target)
                
            elif choice == "9":
                self.generate_security_report()
                
            elif choice == "10":
                print("Exiting...")
                sys.exit()
                
            else:
                print("Invalid choice!")

if __name__ == "__main__":
    toolkit = BlueTeamToolkit()
    print("Welcome to Blue Team Security Toolkit")
    toolkit.menu()