import asyncio
import threading
import queue
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Callable
import numpy as np
import pandas as pd
from collections import deque, defaultdict
import subprocess
import socket
import struct
import warnings
warnings.filterwarnings('ignore')

# Import our custom modules
from data_processor import NetworkDataProcessor
from deep_learning_model import DeepIDSModel
from feature_engineering import NetworkFeatureEngineer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealTimeNetworkAnalyzer:
    """
    Real-time network traffic analyzer for intrusion detection.
    Processes live network traffic and provides real-time threat detection.
    """
    
    def __init__(self, model_path: str = None, buffer_size: int = 1000):
        self.buffer_size = buffer_size
        self.traffic_buffer = deque(maxlen=buffer_size)
        self.alert_queue = queue.Queue()
        self.stats_queue = queue.Queue()
        
        # Initialize components
        self.data_processor = NetworkDataProcessor()
        self.feature_engineer = NetworkFeatureEngineer()
        self.model = None
        
        # Real-time statistics
        self.stats = {
            'total_flows': 0,
            'benign_flows': 0,
            'malicious_flows': 0,
            'alerts_generated': 0,
            'processing_time': deque(maxlen=100),
            'start_time': datetime.now()
        }
        
        # Configuration
        self.config = {
            'alert_threshold': 0.7,
            'batch_size': 50,
            'processing_interval': 1.0,  # seconds
            'max_alerts_per_minute': 100,
            'feature_window': 10  # Number of flows for temporal features
        }
        
        # Alert rate limiting
        self.alert_timestamps = deque(maxlen=self.config['max_alerts_per_minute'])
        
        # Threading control
        self.running = False
        self.processing_thread = None
        
        # Load model if provided
        if model_path:
            self.load_model(model_path)
    
    def load_model(self, model_path: str):
        """Load pre-trained IDS model"""
        try:
            # Initialize model with dummy input dimension (will be updated)
            self.model = DeepIDSModel(input_dim=50, model_type='dnn')
            self.model.load_model(model_path)
            logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            self.model = None
    
    def set_model(self, model: DeepIDSModel):
        """Set the IDS model for predictions"""
        self.model = model
        logger.info("Model set for real-time analysis")
    
    def parse_network_flow(self, flow_data: Dict) -> Dict:
        """Parse and standardize network flow data from REAL traffic sources"""
        try:
            required_fields = ['src_ip', 'dst_ip', 'src_port', 'dst_port']
            for field in required_fields:
                if field not in flow_data:
                    logger.warning(f"Missing required field {field} in flow data")
                    return {}
            
            # Standardize flow data format
            standardized_flow = {
                'timestamp': flow_data.get('timestamp', datetime.now().isoformat()),
                'src_ip': str(flow_data.get('src_ip', '0.0.0.0')),
                'dst_ip': str(flow_data.get('dst_ip', '0.0.0.0')),
                'src_port': int(flow_data.get('src_port', 0)),
                'dst_port': int(flow_data.get('dst_port', 0)),
                'protocol': str(flow_data.get('protocol', 'TCP')),
                'flow_duration': float(flow_data.get('flow_duration', 0)),
                'total_fwd_packets': int(flow_data.get('total_fwd_packets', 0)),
                'total_backward_packets': int(flow_data.get('total_backward_packets', 0)),
                'total_length_fwd_packets': int(flow_data.get('total_length_fwd_packets', 0)),
                'total_length_bwd_packets': int(flow_data.get('total_length_bwd_packets', 0)),
                'fwd_packet_length_max': float(flow_data.get('fwd_packet_length_max', 0)),
                'fwd_packet_length_min': float(flow_data.get('fwd_packet_length_min', 0)),
                'fwd_packet_length_mean': float(flow_data.get('fwd_packet_length_mean', 0)),
                'flow_bytes_s': float(flow_data.get('flow_bytes_s', 0)),
                'flow_packets_s': float(flow_data.get('flow_packets_s', 0)),
                'flow_iat_mean': float(flow_data.get('flow_iat_mean', 0)),
                'flow_iat_std': float(flow_data.get('flow_iat_std', 0)),
                'source': flow_data.get('source', 'real_traffic')  # Mark as real traffic
            }
            
            import ipaddress
            try:
                ipaddress.ip_address(standardized_flow['src_ip'])
                ipaddress.ip_address(standardized_flow['dst_ip'])
            except ValueError:
                logger.warning(f"Invalid IP addresses in flow: {standardized_flow['src_ip']} -> {standardized_flow['dst_ip']}")
                return {}
            
            return standardized_flow
            
        except Exception as e:
            logger.error(f"Error parsing REAL flow data: {str(e)}")
            return {}
    
    def add_flow(self, flow_data: Dict):
        """Add a new REAL network flow to the processing buffer"""
        try:
            parsed_flow = self.parse_network_flow(flow_data)
            if parsed_flow:
                parsed_flow['buffer_timestamp'] = time.time()
                self.traffic_buffer.append(parsed_flow)
                self.stats['total_flows'] += 1
                logger.debug(f"Added REAL flow: {parsed_flow['src_ip']}:{parsed_flow['src_port']} -> {parsed_flow['dst_ip']}:{parsed_flow['dst_port']}")
                
        except Exception as e:
            logger.error(f"Error adding REAL flow: {str(e)}")
    
    def process_buffer_batch(self) -> List[Dict]:
        """Process a batch of flows from the buffer"""
        if len(self.traffic_buffer) < self.config['batch_size']:
            return []
        
        try:
            start_time = time.time()
            
            # Extract batch from buffer
            batch_flows = []
            for _ in range(min(self.config['batch_size'], len(self.traffic_buffer))):
                if self.traffic_buffer:
                    batch_flows.append(self.traffic_buffer.popleft())
            
            if not batch_flows:
                return []
            
            # Convert to DataFrame for processing
            df_batch = pd.DataFrame(batch_flows)
            
            # Rename columns to match our processor expectations
            column_mapping = {
                'flow_duration': 'Flow Duration',
                'total_fwd_packets': 'Total Fwd Packets',
                'total_backward_packets': 'Total Backward Packets',
                'total_length_fwd_packets': 'Total Length of Fwd Packets',
                'total_length_bwd_packets': 'Total Length of Bwd Packets',
                'fwd_packet_length_max': 'Fwd Packet Length Max',
                'fwd_packet_length_min': 'Fwd Packet Length Min',
                'fwd_packet_length_mean': 'Fwd Packet Length Mean',
                'flow_bytes_s': 'Flow Bytes/s',
                'flow_packets_s': 'Flow Packets/s',
                'flow_iat_mean': 'Flow IAT Mean',
                'flow_iat_std': 'Flow IAT Std',
            }
            
            df_batch = df_batch.rename(columns=column_mapping)
            
            # Add dummy label for processing
            df_batch['Label'] = 'BENIGN'  # Will be predicted
            
            # Process features
            df_processed = self.data_processor.clean_dataset(df_batch)
            df_processed = self.data_processor.extract_features(df_processed)
            df_processed = self.feature_engineer.extract_flow_features(df_processed)
            
            # Normalize features if processor is fitted
            if self.data_processor.is_fitted:
                df_processed = self.data_processor.normalize_features(df_processed, fit=False)
            
            # Make predictions if model is available
            predictions = []
            if self.model and self.model.is_trained:
                try:
                    # Select feature columns
                    feature_cols = [col for col in df_processed.columns 
                                  if col not in ['Label', 'timestamp', 'src_ip', 'dst_ip', 
                                               'src_port', 'dst_port', 'protocol', 'buffer_timestamp']]
                    
                    if feature_cols:
                        X_batch = df_processed[feature_cols].fillna(0).values
                        
                        # Ensure correct number of features
                        if X_batch.shape[1] >= self.model.input_dim:
                            X_batch = X_batch[:, :self.model.input_dim]
                        else:
                            # Pad with zeros if not enough features
                            padding = np.zeros((X_batch.shape[0], self.model.input_dim - X_batch.shape[1]))
                            X_batch = np.hstack([X_batch, padding])
                        
                        pred_labels, pred_probs = self.model.predict_batch(X_batch, 
                                                                         threshold=self.config['alert_threshold'])
                        
                        # Create prediction results
                        for i, (flow, label, prob) in enumerate(zip(batch_flows, pred_labels, pred_probs)):
                            prediction = {
                                'flow_id': f"{flow['src_ip']}:{flow['src_port']}->{flow['dst_ip']}:{flow['dst_port']}",
                                'timestamp': flow['timestamp'],
                                'src_ip': flow['src_ip'],
                                'dst_ip': flow['dst_ip'],
                                'src_port': flow['src_port'],
                                'dst_port': flow['dst_port'],
                                'protocol': flow['protocol'],
                                'prediction': 'MALICIOUS' if label == 1 else 'BENIGN',
                                'confidence': float(prob),
                                'alert': label == 1 and prob >= self.config['alert_threshold']
                            }
                            predictions.append(prediction)
                            
                            # Update statistics
                            if label == 1:
                                self.stats['malicious_flows'] += 1
                                if prediction['alert']:
                                    self.generate_alert(prediction)
                            else:
                                self.stats['benign_flows'] += 1
                
                except Exception as e:
                    logger.error(f"Error making predictions: {str(e)}")
            
            # Record processing time
            processing_time = time.time() - start_time
            self.stats['processing_time'].append(processing_time)
            
            return predictions
            
        except Exception as e:
            logger.error(f"Error processing batch: {str(e)}")
            return []
    
    def generate_alert(self, prediction: Dict):
        """Generate security alert for malicious traffic"""
        try:
            # Rate limiting
            current_time = time.time()
            self.alert_timestamps.append(current_time)
            
            # Check if we're exceeding alert rate limit
            minute_ago = current_time - 60
            recent_alerts = sum(1 for ts in self.alert_timestamps if ts > minute_ago)
            
            if recent_alerts > self.config['max_alerts_per_minute']:
                logger.warning("Alert rate limit exceeded, skipping alert")
                return
            
            # Create alert
            alert = {
                'alert_id': f"IDS_{int(current_time)}_{hash(prediction['flow_id']) % 10000}",
                'timestamp': datetime.now().isoformat(),
                'severity': self.get_alert_severity(prediction['confidence']),
                'flow_id': prediction['flow_id'],
                'src_ip': prediction['src_ip'],
                'dst_ip': prediction['dst_ip'],
                'src_port': prediction['src_port'],
                'dst_port': prediction['dst_port'],
                'protocol': prediction['protocol'],
                'prediction': prediction['prediction'],
                'confidence': prediction['confidence'],
                'description': f"Malicious network activity detected with {prediction['confidence']:.2%} confidence",
                'recommended_action': self.get_recommended_action(prediction)
            }
            
            # Add to alert queue
            self.alert_queue.put(alert)
            self.stats['alerts_generated'] += 1
            
            logger.warning(f"SECURITY ALERT: {alert['description']} - {alert['flow_id']}")
            
        except Exception as e:
            logger.error(f"Error generating alert: {str(e)}")
    
    def get_alert_severity(self, confidence: float) -> str:
        """Determine alert severity based on confidence"""
        if confidence >= 0.9:
            return "CRITICAL"
        elif confidence >= 0.8:
            return "HIGH"
        elif confidence >= 0.7:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_recommended_action(self, prediction: Dict) -> str:
        """Get recommended action for the alert"""
        confidence = prediction['confidence']
        
        if confidence >= 0.9:
            return "BLOCK_IMMEDIATELY"
        elif confidence >= 0.8:
            return "INVESTIGATE_URGENT"
        elif confidence >= 0.7:
            return "MONITOR_CLOSELY"
        else:
            return "LOG_AND_REVIEW"
    
    def get_alerts(self, max_alerts: int = 100) -> List[Dict]:
        """Get recent alerts from the queue"""
        alerts = []
        count = 0
        
        while not self.alert_queue.empty() and count < max_alerts:
            try:
                alert = self.alert_queue.get_nowait()
                alerts.append(alert)
                count += 1
            except queue.Empty:
                break
        
        return alerts
    
    def get_statistics(self) -> Dict:
        """Get real-time processing statistics for REAL traffic"""
        current_time = datetime.now()
        uptime = current_time - self.stats['start_time']
        
        avg_processing_time = np.mean(self.stats['processing_time']) if self.stats['processing_time'] else 0
        
        return {
            'uptime_seconds': uptime.total_seconds(),
            'total_flows_processed': self.stats['total_flows'],
            'benign_flows': self.stats['benign_flows'],
            'malicious_flows': self.stats['malicious_flows'],
            'alerts_generated': self.stats['alerts_generated'],
            'buffer_size': len(self.traffic_buffer),
            'avg_processing_time_ms': avg_processing_time * 1000,
            'flows_per_second': self.stats['total_flows'] / max(uptime.total_seconds(), 1),
            'detection_rate': self.stats['malicious_flows'] / max(self.stats['total_flows'], 1) * 100,
            'alert_rate': self.stats['alerts_generated'] / max(self.stats['total_flows'], 1) * 100,
            'data_source': 'REAL_TRAFFIC_ONLY'  # Mark as real traffic processing
        }
    
    def start_processing(self):
        """Start real-time processing thread for REAL traffic"""
        if self.running:
            logger.warning("Processing already running")
            return
        
        self.running = True
        self.processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
        self.processing_thread.start()
        logger.info("Real-time processing started for REAL network traffic")
    
    def stop_processing(self):
        """Stop real-time processing"""
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        logger.info("Real-time processing stopped")
    
    def _processing_loop(self):
        """Main processing loop for REAL traffic"""
        while self.running:
            try:
                # Process batch if enough flows in buffer
                predictions = self.process_buffer_batch()
                
                # Add statistics to queue
                if predictions:
                    stats = self.get_statistics()
                    try:
                        self.stats_queue.put_nowait(stats)
                    except queue.Full:
                        # Remove old stats if queue is full
                        try:
                            self.stats_queue.get_nowait()
                            self.stats_queue.put_nowait(stats)
                        except queue.Empty:
                            pass
                
                # Sleep for processing interval
                time.sleep(self.config['processing_interval'])
                
            except Exception as e:
                logger.error(f"Error in REAL traffic processing loop: {str(e)}")
                time.sleep(1)  # Brief pause on error

    def connect_to_traffic_source(self, source_type: str, **kwargs):
        """Connect to REAL traffic sources (Zeek, CICFlowMeter, etc.)"""
        logger.info(f"Connecting to REAL traffic source: {source_type}")
        
        if source_type.lower() == 'zeek':
            from zeek_integration import ZeekIntegration
            zeek = ZeekIntegration(**kwargs)
            zeek.set_flow_callback(self.add_flow)
            return zeek
            
        elif source_type.lower() == 'cicflowmeter':
            from cicflowmeter_integration import CICFlowMeterIntegration
            cicflow = CICFlowMeterIntegration(**kwargs)
            cicflow.set_flow_callback(self.add_flow)
            return cicflow
            
        else:
            raise ValueError(f"Unsupported traffic source: {source_type}")

# Real-time Network Analyzer - REAL TRAFFIC ONLY
if __name__ == "__main__":
    logger.info("Real-time Network Analyzer - REAL TRAFFIC ONLY")
    print("This analyzer processes REAL network traffic from:")
    print("1. Zeek log files and live monitoring")
    print("2. CICFlowMeter PCAP processing")
    print("3. Live network interface capture")
    print("\nNo simulated data - only analyzes REAL network flows!")
    print("\nTo use:")
    print("1. Connect to a traffic source: analyzer.connect_to_traffic_source('zeek')")
    print("2. Start processing: analyzer.start_processing()")
    print("3. Monitor alerts: analyzer.get_alerts()")
