import subprocess
import json
import time
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Callable
import pandas as pd
from datetime import datetime
import queue
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ZeekIntegration:
    """
    Integration with Zeek (formerly Bro) network security monitor.
    Processes Zeek logs in real-time for intrusion detection.
    """
    
    def __init__(self, zeek_path: str = "/usr/local/zeek/bin/zeek", 
                 log_dir: str = "./zeek_logs"):
        self.zeek_path = zeek_path
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Zeek process management
        self.zeek_process = None
        self.monitoring = False
        self.monitor_thread = None
        
        # Data queues
        self.flow_queue = queue.Queue(maxsize=10000)
        self.log_files = {}
        
        # Callbacks
        self.flow_callback = None
        
        # Zeek log file mappings
        self.log_mappings = {
            'conn.log': self._parse_conn_log,
            'dns.log': self._parse_dns_log,
            'http.log': self._parse_http_log,
            'ssl.log': self._parse_ssl_log,
            'weird.log': self._parse_weird_log
        }
        
        # Check if Zeek is available
        self._check_zeek_availability()
    
    def _check_zeek_availability(self):
        """Check if Zeek is installed and accessible"""
        try:
            result = subprocess.run([self.zeek_path, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info(f"Zeek found: {result.stdout.strip()}")
                return True
            else:
                logger.warning("Zeek not found or not working properly")
                return False
        except Exception as e:
            logger.warning(f"Zeek not available: {str(e)}")
            return False
    
    def start_zeek_monitoring(self, interface: str = "eth0", 
                            custom_scripts: List[str] = None):
        """Start Zeek monitoring on specified interface"""
        try:
            if self.zeek_process and self.zeek_process.poll() is None:
                logger.warning("Zeek is already running")
                return
            
            # Prepare Zeek command
            cmd = [
                self.zeek_path,
                "-i", interface,
                "-C",  # Ignore checksums
                f"Log::default_logdir={self.log_dir}"
            ]
            
            # Add custom scripts if provided
            if custom_scripts:
                cmd.extend(custom_scripts)
            else:
                # Use default scripts for network monitoring
                cmd.extend([
                    "protocols/conn",
                    "protocols/dns", 
                    "protocols/http",
                    "protocols/ssl",
                    "base/misc/weird"
                ])
            
            logger.info(f"Starting Zeek with command: {' '.join(cmd)}")
            
            # Start Zeek process
            self.zeek_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.log_dir
            )
            
            # Start log monitoring
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_logs, daemon=True)
            self.monitor_thread.start()
            
            logger.info("Zeek monitoring started successfully")
            
        except Exception as e:
            logger.error(f"Error starting Zeek: {str(e)}")
            raise
    
    def stop_zeek_monitoring(self):
        """Stop Zeek monitoring"""
        try:
            self.monitoring = False
            
            if self.zeek_process:
                self.zeek_process.terminate()
                try:
                    self.zeek_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.zeek_process.kill()
                    self.zeek_process.wait()
                
                self.zeek_process = None
            
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)
            
            logger.info("Zeek monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping Zeek: {str(e)}")
    
    def _monitor_logs(self):
        """Monitor Zeek log files for new entries"""
        logger.info("Starting log file monitoring")
        
        # Track file positions
        file_positions = {}
        
        while self.monitoring:
            try:
                # Check for new log files
                for log_file in self.log_dir.glob("*.log"):
                    if log_file.name not in file_positions:
                        file_positions[log_file.name] = 0
                        logger.info(f"Started monitoring {log_file.name}")
                
                # Process each log file
                for log_filename, position in file_positions.items():
                    log_path = self.log_dir / log_filename
                    
                    if log_path.exists():
                        try:
                            with open(log_path, 'r') as f:
                                f.seek(position)
                                new_lines = f.readlines()
                                file_positions[log_filename] = f.tell()
                                
                                if new_lines:
                                    self._process_log_lines(log_filename, new_lines)
                                    
                        except Exception as e:
                            logger.error(f"Error reading {log_filename}: {str(e)}")
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in log monitoring: {str(e)}")
                time.sleep(5)  # Wait longer on error
    
    def _process_log_lines(self, log_filename: str, lines: List[str]):
        """Process new lines from Zeek log files"""
        try:
            if log_filename in self.log_mappings:
                parser = self.log_mappings[log_filename]
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            parsed_data = parser(line)
                            if parsed_data:
                                # Add to flow queue
                                if not self.flow_queue.full():
                                    self.flow_queue.put(parsed_data)
                                
                                # Call callback if set
                                if self.flow_callback:
                                    self.flow_callback(parsed_data)
                                    
                        except Exception as e:
                            logger.debug(f"Error parsing line from {log_filename}: {str(e)}")
                            
        except Exception as e:
            logger.error(f"Error processing lines from {log_filename}: {str(e)}")
    
    def _parse_conn_log(self, line: str) -> Optional[Dict]:
        """Parse Zeek conn.log entry"""
        try:
            fields = line.split('\t')
            if len(fields) < 15:
                return None
            
            # Map Zeek conn.log fields to our format
            flow_data = {
                'timestamp': datetime.fromtimestamp(float(fields[0])).isoformat(),
                'src_ip': fields[2],
                'src_port': int(fields[3]) if fields[3] != '-' else 0,
                'dst_ip': fields[4], 
                'dst_port': int(fields[5]) if fields[5] != '-' else 0,
                'protocol': fields[6],
                'flow_duration': float(fields[8]) * 1000000 if fields[8] != '-' else 0,  # Convert to microseconds
                'total_fwd_packets': int(fields[9]) if fields[9] != '-' else 0,
                'total_backward_packets': int(fields[10]) if fields[10] != '-' else 0,
                'total_length_fwd_packets': int(fields[11]) if fields[11] != '-' else 0,
                'total_length_bwd_packets': int(fields[12]) if fields[12] != '-' else 0,
                'zeek_log_type': 'conn',
                'zeek_uid': fields[1],
                'connection_state': fields[13] if len(fields) > 13 else '-'
            }
            
            # Calculate additional features
            total_packets = flow_data['total_fwd_packets'] + flow_data['total_backward_packets']
            total_bytes = flow_data['total_length_fwd_packets'] + flow_data['total_length_bwd_packets']
            
            if flow_data['flow_duration'] > 0:
                flow_data['flow_bytes_s'] = total_bytes / (flow_data['flow_duration'] / 1000000)
                flow_data['flow_packets_s'] = total_packets / (flow_data['flow_duration'] / 1000000)
            else:
                flow_data['flow_bytes_s'] = 0
                flow_data['flow_packets_s'] = 0
            
            # Calculate packet size statistics
            if flow_data['total_fwd_packets'] > 0:
                flow_data['fwd_packet_length_mean'] = flow_data['total_length_fwd_packets'] / flow_data['total_fwd_packets']
            else:
                flow_data['fwd_packet_length_mean'] = 0
            
            # Set default values for missing features
            flow_data['fwd_packet_length_max'] = flow_data['fwd_packet_length_mean'] * 1.5
            flow_data['fwd_packet_length_min'] = max(20, flow_data['fwd_packet_length_mean'] * 0.5)
            flow_data['flow_iat_mean'] = flow_data['flow_duration'] / max(total_packets, 1)
            flow_data['flow_iat_std'] = flow_data['flow_iat_mean'] * 0.3
            
            return flow_data
            
        except Exception as e:
            logger.debug(f"Error parsing conn.log line: {str(e)}")
            return None
    
    def _parse_dns_log(self, line: str) -> Optional[Dict]:
        """Parse Zeek dns.log entry"""
        try:
            fields = line.split('\t')
            if len(fields) < 10:
                return None
            
            # Create flow data for DNS queries
            flow_data = {
                'timestamp': datetime.fromtimestamp(float(fields[0])).isoformat(),
                'src_ip': fields[2],
                'src_port': int(fields[3]) if fields[3] != '-' else 53,
                'dst_ip': fields[4],
                'dst_port': int(fields[5]) if fields[5] != '-' else 53,
                'protocol': fields[6],
                'zeek_log_type': 'dns',
                'zeek_uid': fields[1],
                'dns_query': fields[9] if len(fields) > 9 else '-',
                'dns_qtype': fields[13] if len(fields) > 13 else '-',
                'dns_rcode': fields[15] if len(fields) > 15 else '-'
            }
            
            # Set default network flow values
            flow_data.update({
                'flow_duration': 100000,  # Typical DNS query duration
                'total_fwd_packets': 1,
                'total_backward_packets': 1,
                'total_length_fwd_packets': 64,  # Typical DNS query size
                'total_length_bwd_packets': 128,  # Typical DNS response size
                'fwd_packet_length_mean': 64,
                'fwd_packet_length_max': 64,
                'fwd_packet_length_min': 64,
                'flow_bytes_s': 1920,  # (64+128) / 0.1s
                'flow_packets_s': 20,   # 2 packets / 0.1s
                'flow_iat_mean': 50000,
                'flow_iat_std': 10000
            })
            
            return flow_data
            
        except Exception as e:
            logger.debug(f"Error parsing dns.log line: {str(e)}")
            return None
    
    def _parse_http_log(self, line: str) -> Optional[Dict]:
        """Parse Zeek http.log entry"""
        try:
            fields = line.split('\t')
            if len(fields) < 15:
                return None
            
            flow_data = {
                'timestamp': datetime.fromtimestamp(float(fields[0])).isoformat(),
                'src_ip': fields[2],
                'src_port': int(fields[3]) if fields[3] != '-' else 80,
                'dst_ip': fields[4],
                'dst_port': int(fields[5]) if fields[5] != '-' else 80,
                'protocol': 'TCP',
                'zeek_log_type': 'http',
                'zeek_uid': fields[1],
                'http_method': fields[7] if len(fields) > 7 else '-',
                'http_host': fields[8] if len(fields) > 8 else '-',
                'http_uri': fields[9] if len(fields) > 9 else '-',
                'http_status_code': fields[12] if len(fields) > 12 else '-'
            }
            
            # Estimate HTTP flow characteristics
            request_size = len(flow_data.get('http_uri', '')) + 200  # Headers + URI
            response_size = 1500  # Typical HTTP response
            
            flow_data.update({
                'flow_duration': 500000,  # 0.5 seconds typical
                'total_fwd_packets': 3,   # Request packets
                'total_backward_packets': 5,  # Response packets
                'total_length_fwd_packets': request_size,
                'total_length_bwd_packets': response_size,
                'fwd_packet_length_mean': request_size / 3,
                'fwd_packet_length_max': request_size,
                'fwd_packet_length_min': 64,
                'flow_bytes_s': (request_size + response_size) / 0.5,
                'flow_packets_s': 16,  # 8 packets / 0.5s
                'flow_iat_mean': 62500,  # 0.5s / 8 packets
                'flow_iat_std': 20000
            })
            
            return flow_data
            
        except Exception as e:
            logger.debug(f"Error parsing http.log line: {str(e)}")
            return None
    
    def _parse_ssl_log(self, line: str) -> Optional[Dict]:
        """Parse Zeek ssl.log entry"""
        try:
            fields = line.split('\t')
            if len(fields) < 10:
                return None
            
            flow_data = {
                'timestamp': datetime.fromtimestamp(float(fields[0])).isoformat(),
                'src_ip': fields[2],
                'src_port': int(fields[3]) if fields[3] != '-' else 443,
                'dst_ip': fields[4],
                'dst_port': int(fields[5]) if fields[5] != '-' else 443,
                'protocol': 'TCP',
                'zeek_log_type': 'ssl',
                'zeek_uid': fields[1],
                'ssl_version': fields[6] if len(fields) > 6 else '-',
                'ssl_server_name': fields[9] if len(fields) > 9 else '-'
            }
            
            # SSL/TLS flow characteristics
            flow_data.update({
                'flow_duration': 2000000,  # 2 seconds for handshake
                'total_fwd_packets': 4,    # Client hello, key exchange, etc.
                'total_backward_packets': 4,  # Server hello, certificate, etc.
                'total_length_fwd_packets': 800,
                'total_length_bwd_packets': 3000,  # Certificates are large
                'fwd_packet_length_mean': 200,
                'fwd_packet_length_max': 400,
                'fwd_packet_length_min': 100,
                'flow_bytes_s': 1900,  # (800+3000) / 2s
                'flow_packets_s': 4,   # 8 packets / 2s
                'flow_iat_mean': 250000,  # 2s / 8 packets
                'flow_iat_std': 100000
            })
            
            return flow_data
            
        except Exception as e:
            logger.debug(f"Error parsing ssl.log line: {str(e)}")
            return None
    
    def _parse_weird_log(self, line: str) -> Optional[Dict]:
        """Parse Zeek weird.log entry (anomalies)"""
        try:
            fields = line.split('\t')
            if len(fields) < 6:
                return None
            
            # Weird events often indicate suspicious activity
            flow_data = {
                'timestamp': datetime.fromtimestamp(float(fields[0])).isoformat(),
                'src_ip': fields[2] if fields[2] != '-' else '0.0.0.0',
                'src_port': int(fields[3]) if fields[3] != '-' and fields[3].isdigit() else 0,
                'dst_ip': fields[4] if fields[4] != '-' else '0.0.0.0',
                'dst_port': int(fields[5]) if fields[5] != '-' and fields[5].isdigit() else 0,
                'protocol': 'TCP',  # Default
                'zeek_log_type': 'weird',
                'zeek_uid': fields[1] if len(fields) > 1 else '-',
                'weird_name': fields[6] if len(fields) > 6 else 'unknown',
                'weird_notice': True  # Flag for potential attack
            }
            
            # Weird events suggest anomalous behavior - set suspicious characteristics
            flow_data.update({
                'flow_duration': 10000,   # Very short
                'total_fwd_packets': 1,
                'total_backward_packets': 0,  # Often no response
                'total_length_fwd_packets': 40,  # Small packets
                'total_length_bwd_packets': 0,
                'fwd_packet_length_mean': 40,
                'fwd_packet_length_max': 40,
                'fwd_packet_length_min': 40,
                'flow_bytes_s': 4000,  # 40 bytes / 0.01s
                'flow_packets_s': 100,
                'flow_iat_mean': 10000,
                'flow_iat_std': 1000
            })
            
            return flow_data
            
        except Exception as e:
            logger.debug(f"Error parsing weird.log line: {str(e)}")
            return None
    
    def set_flow_callback(self, callback: Callable[[Dict], None]):
        """Set callback function for new flow data"""
        self.flow_callback = callback
        logger.info("Flow callback set")
    
    def get_flows(self, max_flows: int = 100) -> List[Dict]:
        """Get flows from the queue"""
        flows = []
        count = 0
        
        while not self.flow_queue.empty() and count < max_flows:
            try:
                flow = self.flow_queue.get_nowait()
                flows.append(flow)
                count += 1
            except queue.Empty:
                break
        
        return flows
    
    def process_existing_logs(self, log_directory: str = None) -> List[Dict]:
        """Process existing Zeek log files"""
        if log_directory:
            log_dir = Path(log_directory)
        else:
            log_dir = self.log_dir
        
        all_flows = []
        
        for log_file in log_dir.glob("*.log"):
            logger.info(f"Processing existing log file: {log_file.name}")
            
            if log_file.name in self.log_mappings:
                parser = self.log_mappings[log_file.name]
                
                try:
                    with open(log_file, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()
                            if line and not line.startswith('#'):
                                try:
                                    parsed_data = parser(line)
                                    if parsed_data:
                                        all_flows.append(parsed_data)
                                except Exception as e:
                                    logger.debug(f"Error parsing line {line_num} in {log_file.name}: {str(e)}")
                                    
                except Exception as e:
                    logger.error(f"Error reading {log_file.name}: {str(e)}")
        
        logger.info(f"Processed {len(all_flows)} flows from existing logs")
        return all_flows

# Example usage and testing
if __name__ == "__main__":
    logger.info("Testing Zeek Integration...")
    
    try:
        # Initialize Zeek integration
        zeek = ZeekIntegration(log_dir="./test_zeek_logs")
        
        # Test with sample log data (simulate Zeek logs)
        sample_conn_log = """1609459200.123456	C1a2b3c4d5e6f7g8	192.168.1.100	12345	10.0.0.1	80	tcp	-	10.5	15	8	1500	800	SF	-	-	0	Cc	3	2048	3	1024	(empty)"""
        
        sample_dns_log = """1609459201.234567	D1a2b3c4d5e6f7g8	192.168.1.100	54321	8.8.8.8	53	udp	12345	0.1	example.com	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	google.com	300.0	T"""
        
        # Test parsing functions
        print("Testing log parsing...")
        
        conn_flow = zeek._parse_conn_log(sample_conn_log)
        if conn_flow:
            print(f"Parsed conn.log: {conn_flow['src_ip']}:{conn_flow['src_port']} -> {conn_flow['dst_ip']}:{conn_flow['dst_port']}")
            print(f"  Duration: {conn_flow['flow_duration']}μs, Packets: {conn_flow['total_fwd_packets']+conn_flow['total_backward_packets']}")
        
        dns_flow = zeek._parse_dns_log(sample_dns_log)
        if dns_flow:
            print(f"Parsed dns.log: {dns_flow['src_ip']} -> {dns_flow['dst_ip']} (query: {dns_flow.get('dns_query', 'N/A')})")
        
        # Test flow callback
        received_flows = []
        
        def flow_callback(flow_data):
            received_flows.append(flow_data)
            print(f"Received flow: {flow_data['src_ip']} -> {flow_data['dst_ip']} ({flow_data.get('zeek_log_type', 'unknown')})")
        
        zeek.set_flow_callback(flow_callback)
        
        # Simulate processing log lines
        print("\nSimulating log processing...")
        zeek._process_log_lines('conn.log', [sample_conn_log])
        zeek._process_log_lines('dns.log', [sample_dns_log])
        
        # Get flows from queue
        flows = zeek.get_flows(max_flows=10)
        print(f"\nRetrieved {len(flows)} flows from queue")
        
        for flow in flows:
            print(f"  {flow['timestamp']}: {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} ({flow.get('zeek_log_type', 'unknown')})")
        
        print(f"\nCallback received {len(received_flows)} flows")
        
        print("\nZeek integration testing completed successfully!")
        
        # Note: Real Zeek monitoring would require:
        # zeek.start_zeek_monitoring(interface="eth0")
        # time.sleep(60)  # Monitor for 60 seconds
        # zeek.stop_zeek_monitoring()
        
    except Exception as e:
        print(f"Error in Zeek integration testing: {str(e)}")
        import traceback
        traceback.print_exc()
