import nmap
import threading
from datetime import datetime
import os
import subprocess
import json
import re

class NetworkScanner:
    def __init__(self):
        self._status = {"status": "idle", "progress": 0, "message": ""}
        self._results = None
        self._lock = threading.Lock()
        
        # Vulnerability database (simplified version)
        self.vuln_database = {
            'http-vuln': {
                'category': 'Web Application',
                'severity': 'High',
                'remediation': 'Update web server software, apply security patches, and implement secure configurations.'
            },
            'ssl-vuln': {
                'category': 'Encryption',
                'severity': 'Critical',
                'remediation': 'Update SSL/TLS to latest version, disable vulnerable ciphers, implement proper certificate management.'
            },
            'smb-vuln': {
                'category': 'Network Service',
                'severity': 'Critical',
                'remediation': 'Update SMB to latest version, disable SMBv1, implement proper access controls.'
            },
            'ms-sql-vuln': {
                'category': 'Database',
                'severity': 'High',
                'remediation': 'Apply latest security patches, implement proper authentication, restrict network access.'
            }
        }
        
        # Find nmap path
        possible_paths = [
            '/opt/homebrew/bin/nmap',
            '/usr/local/bin/nmap',
            '/usr/bin/nmap'
        ]
        
        nmap_path = None
        for path in possible_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                nmap_path = path
                break
                
        if not nmap_path:
            try:
                nmap_path = subprocess.check_output(['which', 'nmap'], 
                                                 stderr=subprocess.STDOUT).decode().strip()
            except subprocess.CalledProcessError:
                raise Exception("Nmap not found. Please install nmap using: brew install nmap")
        
        try:
            self._nm = nmap.PortScanner()
        except Exception as e:
            raise Exception(f"Error initializing nmap: {str(e)}")
    
    def analyze_vulnerability(self, script_id, output):
        """Analyze vulnerability output and provide detailed information"""
        severity = "Medium"  # Default severity
        risk_score = 5.0    # Default risk score (0-10)
        
        # Analyze severity based on keywords
        critical_keywords = ['critical', 'remote code execution', 'arbitrary code', 'overflow']
        high_keywords = ['high', 'vulnerability', 'exploit', 'bypass']
        low_keywords = ['information disclosure', 'version detection']
        
        output_lower = output.lower()
        
        if any(keyword in output_lower for keyword in critical_keywords):
            severity = "Critical"
            risk_score = 9.0
        elif any(keyword in output_lower for keyword in high_keywords):
            severity = "High"
            risk_score = 7.0
        elif any(keyword in output_lower for keyword in low_keywords):
            severity = "Low"
            risk_score = 3.0
            
        # Get CVE numbers if present
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_numbers = re.findall(cve_pattern, output)
        
        # Get vulnerability category and remediation
        vuln_info = self.vuln_database.get(script_id, {
            'category': 'General',
            'severity': severity,
            'remediation': 'Update affected software and apply security patches.'
        })
        
        return {
            'id': script_id,
            'output': output,
            'severity': severity,
            'risk_score': risk_score,
            'cve_numbers': cve_numbers,
            'category': vuln_info['category'],
            'remediation': vuln_info['remediation']
        }

    def start_scan(self, target, ports, options):
        try:
            with self._lock:
                self._status = {
                    "status": "running",
                    "progress": 0,
                    "message": "Initializing scan..."
                }
            
            # Enhanced scan arguments for better vulnerability detection
            scan_args = '-sT -sV'  # Version detection enabled by default
            
            if options.get('vuln_scan'):
                # Add comprehensive vulnerability scripts
                scan_args += ' --script=vuln,auth,default,discovery,version'
            
            self._update_status("running", 20, f"Scanning {target}...")
            
            try:
                scan_result = self._nm.scan(hosts=target, ports=ports, arguments=scan_args)
            except Exception as e:
                raise Exception(f"Scan failed: {str(e)}")
            
            results = []
            vulnerabilities_summary = {
                'total_count': 0,
                'severity_counts': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
                'categories': {}
            }
            
            for host in self._nm.all_hosts():
                host_info = {
                    "host": host,
                    "hostname": self._nm[host].hostname() if hasattr(self._nm[host], 'hostname') else '',
                    "state": self._nm[host].state(),
                    "ports": [],
                    "vulnerabilities": [],
                    "security_recommendations": []
                }
                
                self._update_status("running", 60, f"Analyzing host {host}...")
                
                # Process ports and services
                for proto in self._nm[host].all_protocols():
                    ports = self._nm[host][proto].keys()
                    for port in sorted(ports):
                        port_info = self._nm[host][proto][port]
                        service_detail = {
                            "port": port,
                            "state": port_info['state'],
                            "service": port_info.get('name', ''),
                            "version": port_info.get('version', ''),
                            "product": port_info.get('product', '')
                        }
                        host_info["ports"].append(service_detail)
                        
                        # Add service-specific security recommendations
                        if port_info.get('name'):
                            self.add_service_recommendations(host_info["security_recommendations"], 
                                                          port_info['name'], 
                                                          port)
                
                # Process vulnerabilities with enhanced analysis
                if 'script' in self._nm[host]:
                    for script_id, output in self._nm[host]['script'].items():
                        vuln_info = self.analyze_vulnerability(script_id, output)
                        host_info["vulnerabilities"].append(vuln_info)
                        
                        # Update vulnerability statistics
                        vulnerabilities_summary['total_count'] += 1
                        vulnerabilities_summary['severity_counts'][vuln_info['severity']] += 1
                        
                        category = vuln_info['category']
                        if category not in vulnerabilities_summary['categories']:
                            vulnerabilities_summary['categories'][category] = 0
                        vulnerabilities_summary['categories'][category] += 1
                
                results.append(host_info)
            
            # Calculate overall security score
            max_score = 100
            deductions = {
                'Critical': 20,
                'High': 10,
                'Medium': 5,
                'Low': 2
            }
            
            security_score = max_score
            for severity, count in vulnerabilities_summary['severity_counts'].items():
                security_score -= count * deductions.get(severity, 0)
            security_score = max(0, security_score)
            
            # Save results with summary
            with self._lock:
                self._results = {
                    "success": True,
                    "data": results,
                    "summary": {
                        "vulnerabilities": vulnerabilities_summary,
                        "security_score": security_score,
                        "scan_time": datetime.now().isoformat()
                    }
                }
                self._status = {
                    "status": "completed",
                    "progress": 100,
                    "message": "Scan completed successfully"
                }
                
        except Exception as e:
            with self._lock:
                self._status = {
                    "status": "error",
                    "progress": 0,
                    "message": f"Error during scan: {str(e)}"
                }
                self._results = {
                    "success": False,
                    "error": str(e)
                }
    
    def add_service_recommendations(self, recommendations, service, port):
        """Add service-specific security recommendations"""
        service_recommendations = {
            'http': [
                f"Ensure HTTP service on port {port} is using HTTPS",
                "Implement secure headers",
                "Enable Web Application Firewall (WAF)",
                "Regular security assessments"
            ],
            'https': [
                f"Verify SSL/TLS configuration on port {port}",
                "Use strong cipher suites",
                "Keep certificates up to date",
                "Enable HSTS"
            ],
            'ssh': [
                f"Configure SSH service on port {port} to use strong algorithms",
                "Implement key-based authentication",
                "Disable root login",
                "Use SSH version 2"
            ],
            'ftp': [
                f"Consider replacing FTP on port {port} with SFTP",
                "Require strong passwords",
                "Implement access controls",
                "Enable encryption"
            ],
            'smb': [
                f"Secure SMB service on port {port}",
                "Disable SMBv1",
                "Implement proper access controls",
                "Regular security updates"
            ]
        }
        
        if service in service_recommendations:
            recommendations.extend(service_recommendations[service])

    def _update_status(self, status, progress, message):
        with self._lock:
            self._status = {
                "status": status,
                "progress": progress,
                "message": message
            }
    
    def get_status(self):
        with self._lock:
            return self._status.copy()
    
    def get_results(self):
        with self._lock:
            return self._results if self._results else {
                "success": False,
                "error": "No results available"
            }