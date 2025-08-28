import subprocess
import json
import csv
import time
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional, Callable
import pandas as pd
from datetime import datetime
import queue
import os
import tempfile
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CICFlowMeterIntegration:
    """
    Integration with Python CICFlowMeter for real-time network flow feature extraction.
    Uses the actual cicflowmeter CLI tool as described in the official documentation.
    """

    def __init__(self, output_dir: str = "./cicflow_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Process management
        self.cicflow_process = None
        self.monitoring = False
        self.monitor_thread = None

        # Data management
        self.flow_queue = queue.Queue(maxsize=10000)
        self.flow_callback = None

        # Check CICFlowMeter installation
        self._check_cicflowmeter_installation()

        # Get available network interfaces
        self.available_interfaces = self._get_network_interfaces()

    def _check_cicflowmeter_installation(self):
        """Check if Python CICFlowMeter is properly installed"""
        try:
            result = subprocess.run(['cicflowmeter', '--help'],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("CICFlowMeter CLI tool found and working")
                return True
            else:
                raise FileNotFoundError("CICFlowMeter command not found")

        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            logger.error(
                "CICFlowMeter not found. Please install using:\n"
                "pip install cicflowmeter\n"
                "or\n"
                "git clone https://gitlab.com/hieulw/cicflowmeter\n"
                "cd cicflowmeter\n"
                "python setup.py install"
            )
            raise

    def _get_network_interfaces(self) -> List[str]:
        """Get available network interfaces using ifconfig"""
        try:
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            if result.returncode != 0:
                # Fallback to ip command on Linux
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)

            interfaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and ('en' in line or 'eth' in line or 'wlan' in line):
                    interface = line.split(':')[0].strip()
                    if interface and not interface.startswith(' '):
                        interfaces.append(interface)

            logger.info(f"Available network interfaces: {interfaces}")
            return interfaces

        except Exception as e:
            logger.warning(f"Could not detect network interfaces: {str(e)}")
            return ['en0', 'eth0', 'wlan0']  # Common defaults

    def start_live_capture(self, interface: str = None, output_file: str = None):
        """Start live network capture using cicflowmeter CLI"""
        try:
            if self.monitoring:
                logger.warning("Live capture already running")
                return

            if interface is None:
                interface = self.available_interfaces[0] if self.available_interfaces else 'en0'

            if output_file is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = self.output_dir / f"live_flows_{timestamp}.csv"

            self.monitoring = True

            self.monitor_thread = threading.Thread(
                target=self._live_capture_loop,
                args=(interface, str(output_file)),
                daemon=True
            )
            self.monitor_thread.start()

            logger.info(f"Started REAL live capture on {interface} -> {output_file}")

        except Exception as e:
            logger.error(f"Error starting live capture: {str(e)}")
            raise

    def _live_capture_loop(self, interface: str, output_file: str):
        """Main loop for REAL live capture using cicflowmeter CLI"""
        try:
            cmd = ['cicflowmeter', '-i', interface, '-c', output_file]

            # Try with sudo if permission denied (as mentioned in article)
            try:
                logger.info(f"Starting REAL packet capture: {' '.join(cmd)}")
                self.cicflow_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            except PermissionError:
                logger.info("Permission denied, trying with sudo...")
                cmd = ['sudo'] + cmd
                self.cicflow_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

            # Monitor the process and output file
            while self.monitoring and self.cicflow_process.poll() is None:
                time.sleep(5)  # Check every 5 seconds

                # Process any new flows that have been written
                if os.path.exists(output_file):
                    self._process_new_flows(output_file)

            # Handle process completion
            if self.cicflow_process.poll() is not None:
                stdout, stderr = self.cicflow_process.communicate()
                if stderr:
                    if "Decimal" in stderr:
                        logger.warning(
                            "Decimal conversion error detected. "
                            "You may need to fix flow.py as mentioned in the documentation: "
                            "Change Decimal('1e6') to float('1e6')"
                        )
                    logger.error(f"CICFlowMeter error: {stderr}")

        except Exception as e:
            logger.error(f"Error in live capture loop: {str(e)}")
        finally:
            self.monitoring = False

    def stop_live_capture(self):
        """Stop live network capture"""
        try:
            self.monitoring = False

            if self.cicflow_process:
                self.cicflow_process.terminate()
                try:
                    self.cicflow_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.cicflow_process.kill()
                    self.cicflow_process.wait()

                self.cicflow_process = None

            if self.monitor_thread:
                self.monitor_thread.join(timeout=5)

            logger.info("Live capture stopped")

        except Exception as e:
            logger.error(f"Error stopping live capture: {str(e)}")

    def process_pcap_file(self, pcap_file: str, output_file: str = None) -> List[Dict]:
        """Process a REAL PCAP file using cicflowmeter CLI"""
        try:
            if not os.path.exists(pcap_file):
                raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

            if output_file is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = self.output_dir / f"flows_{timestamp}.csv"

            cmd = ['cicflowmeter', '-f', pcap_file, '-c', str(output_file)]

            logger.info(f"Processing REAL PCAP file: {pcap_file}")
            logger.info(f"Command: {' '.join(cmd)}")

            # Run cicflowmeter
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if process.returncode != 0:
                if "Decimal" in process.stderr:
                    logger.error(
                        "Decimal conversion error. Fix by changing Decimal('1e6') to float('1e6') "
                        "in the cicflowmeter flow.py file"
                    )
                logger.error(f"CICFlowMeter error: {process.stderr}")
                return []

            # Process the generated CSV file
            if os.path.exists(output_file):
                flows = self._read_flows_from_csv(output_file)
                logger.info(f"Processed {len(flows)} REAL flows from {pcap_file}")
                return flows
            else:
                logger.warning(f"No output file generated: {output_file}")
                return []

        except Exception as e:
            logger.error(f"Error processing REAL PCAP file: {str(e)}")
            return []

    def _process_new_flows(self, csv_file: str):
        """Process new flows from CSV file"""
        try:
            if not os.path.exists(csv_file):
                return

            # Read the CSV file
            flows = self._read_flows_from_csv(csv_file)

            # Add new flows to queue and call callback
            for flow in flows:
                if not self.flow_queue.full():
                    self.flow_queue.put(flow)

                if self.flow_callback:
                    self.flow_callback(flow)

        except Exception as e:
            logger.debug(f"Error processing new flows: {str(e)}")

    def _read_flows_from_csv(self, csv_file: str) -> List[Dict]:
        """Read and convert flows from CICFlowMeter CSV output"""
        try:
            df = pd.read_csv(csv_file)
            flows = []

            for _, row in df.iterrows():
                flow_data = self._convert_cicflow_row(row)
                if flow_data:
                    flows.append(flow_data)

            return flows

        except Exception as e:
            logger.error(f"Error reading CSV file {csv_file}: {str(e)}")
            return []

    def _convert_cicflow_row(self, row: pd.Series) -> Optional[Dict]:
        """Convert CICFlowMeter CSV row to our flow format"""
        try:
            flow_data = {
                'timestamp': datetime.now().isoformat(),
                'source': 'cicflowmeter_real'  # Mark as real data
            }

            # Map CICFlowMeter features to our format
            feature_mapping = {
                'Flow Duration': 'flow_duration',
                'Total Fwd Packets': 'total_fwd_packets',
                'Total Backward Packets': 'total_backward_packets',
                'Total Length of Fwd Packets': 'total_length_fwd_packets',
                'Total Length of Bwd Packets': 'total_length_bwd_packets',
                'Fwd Packet Length Max': 'fwd_packet_length_max',
                'Fwd Packet Length Min': 'fwd_packet_length_min',
                'Fwd Packet Length Mean': 'fwd_packet_length_mean',
                'Flow Bytes/s': 'flow_bytes_s',
                'Flow Packets/s': 'flow_packets_s',
                'Flow IAT Mean': 'flow_iat_mean',
                'Flow IAT Std': 'flow_iat_std',
                'Src IP': 'src_ip',
                'Src Port': 'src_port',
                'Dst IP': 'dst_ip',
                'Dst Port': 'dst_port',
                'Protocol': 'protocol'
            }

            for cicflow_name, our_name in feature_mapping.items():
                if cicflow_name in row.index:
                    value = row[cicflow_name]

                    # Handle different data types
                    if pd.isna(value):
                        value = 0
                    elif isinstance(value, str):
                        if value.replace('.', '').replace('-', '').isdigit():
                            value = float(value)
                        else:
                            # Keep as string for IP addresses, etc.
                            pass

                    flow_data[our_name] = value

            # Ensure required fields exist
            required_fields = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
            for field in required_fields:
                if field not in flow_data:
                    flow_data[field] = '0.0.0.0' if 'ip' in field else 0

            return flow_data

        except Exception as e:
            logger.debug(f"Error converting CICFlowMeter row: {str(e)}")
            return None

    def set_flow_callback(self, callback: Callable[[Dict], None]):
        """Set callback function for new flow data"""
        self.flow_callback = callback
        logger.info("Flow callback set for REAL traffic processing")

    def get_flows(self, max_flows: int = 100) -> List[Dict]:
        """Get REAL flows from the queue"""
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

    def get_system_info(self) -> Dict:
        """Get system information for CICFlowMeter"""
        return {
            'cicflowmeter_available': self._check_cicflowmeter_available(),
            'available_interfaces': self.available_interfaces,
            'output_directory': str(self.output_dir),
            'monitoring_status': self.monitoring,
            'queue_size': self.flow_queue.qsize()
        }

    def _check_cicflowmeter_available(self) -> bool:
        """Check if cicflowmeter command is available"""
        try:
            subprocess.run(['cicflowmeter', '--help'],
                           capture_output=True, timeout=5)
            return True
        except:
            return False


if __name__ == "__main__":
    logger.info("CICFlowMeter Integration - Using Real CLI Tool")
    print("This integration uses the actual cicflowmeter CLI tool:")
    print("1. Install: pip install cicflowmeter")
    print("2. For live capture: cicflowmeter -i <interface> -c <output.csv>")
    print("3. For PCAP files: cicflowmeter -f <file.pcap> -c <output.csv>")
    print("4. May require sudo for live capture")
    print("5. Fix Decimal errors by changing Decimal('1e6') to float('1e6') in flow.py")
    print("\nProcesses REAL network traffic only!")
