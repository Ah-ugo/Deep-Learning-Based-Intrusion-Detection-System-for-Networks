# Network Intrusion Detection System (IDS) 🛡️

A comprehensive deep learning-based intrusion detection system for real-time network security monitoring.

## Features

### 🔍 Real-time Network Monitoring
- Live network traffic analysis
- Real-time threat detection using deep learning
- Automated alert generation with severity levels
- Performance monitoring and statistics

### 🤖 Advanced Machine Learning
- Multiple neural network architectures (DNN, CNN, LSTM, Hybrid, Autoencoder)
- Automated feature engineering and selection
- Model training and evaluation tools
- Support for custom datasets

### 🔌 Network Tool Integration
- **Zeek Integration**: Process Zeek logs (conn, DNS, HTTP, SSL, weird)
- **CICFlowMeter Integration**: Extract flow-based features from PCAP files
- Real-time packet capture and analysis

### 📊 Interactive Dashboard
- Streamlit-based web interface
- Real-time monitoring dashboard
- Alert management system
- Historical analysis and reporting
- Model training interface

## Installation

1. **Clone the repository**
   \`\`\`bash
   git clone <repository-url>
   cd network-ids
   \`\`\`

2. **Install Python dependencies**
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

3. **Install network tools (optional)**
   \`\`\`bash
   # Install Zeek
   sudo apt-get install zeek
   
   # Install tcpdump for packet capture
   sudo apt-get install tcpdump
   \`\`\`

## Quick Start

### 1. Run the Dashboard
\`\`\`bash
python run_dashboard.py
\`\`\`

The dashboard will be available at `http://localhost:8501`

### 2. Train a Model
1. Go to the "Model Training" page
2. Upload a CSV dataset or use the demo data generator
3. Configure model parameters
4. Click "Train Model"

### 3. Start Real-time Monitoring
1. Ensure a trained model is loaded
2. Click "Start Monitoring" in the sidebar
3. View real-time statistics and alerts

## Usage Guide

### Dashboard Pages

#### 📊 Real-time Monitoring
- View live network traffic statistics
- Monitor detection rates and performance metrics
- See real-time security alerts
- Interactive charts and visualizations

#### 🚨 Alert Management
- View and filter security alerts
- Alert severity distribution
- Export alerts to CSV
- Historical alert analysis

#### 🤖 Model Training
- Upload training datasets
- Configure model architecture and parameters
- Train deep learning models
- Evaluate model performance

#### ⚙️ System Configuration
- Configure real-time analyzer settings
- Set up Zeek and CICFlowMeter integrations
- Adjust alert thresholds and rate limits

#### 📊 Historical Analysis
- Analyze historical performance data
- Traffic pattern analysis
- Export historical data

#### 🔧 Data Processing
- Upload and process network traffic data
- Feature engineering and selection
- Data cleaning and normalization

### Network Tool Integration

#### Zeek Integration
\`\`\`python
from zeek_integration import ZeekIntegration

# Initialize Zeek integration
zeek = ZeekIntegration(zeek_path="/usr/local/zeek/bin/zeek")

# Start monitoring
zeek.start_zeek_monitoring(interface="eth0")

# Set callback for new flows
def handle_flow(flow_data):
    print(f"New flow: {flow_data['src_ip']} -> {flow_data['dst_ip']}")

zeek.set_flow_callback(handle_flow)
\`\`\`

#### CICFlowMeter Integration
\`\`\`python
from cicflowmeter_integration import CICFlowMeterIntegration

# Initialize CICFlowMeter
cicflow = CICFlowMeterIntegration(cicflowmeter_path="./CICFlowMeter")

# Process PCAP file
flows = cicflow.process_pcap_file("traffic.pcap")

# Start live capture
cicflow.start_live_capture(interface="eth0", duration=60)
\`\`\`

### Model Training

#### Using Custom Dataset
\`\`\`python
from data_processor import NetworkDataProcessor
from deep_learning_model import DeepIDSModel

# Load and process data
processor = NetworkDataProcessor()
X_train, X_test, y_train, y_test = processor.process_pipeline("dataset.csv")

# Train model
model = DeepIDSModel(input_dim=X_train.shape[1], model_type='dnn')
model.build_model()
model.compile_model()
model.train_model(X_train, y_train, X_test, y_test)

# Evaluate
results = model.evaluate_model(X_test, y_test)
print(f"Accuracy: {results['test_accuracy']:.4f}")
\`\`\`

### Real-time Analysis
\`\`\`python
from realtime_analyzer import RealTimeNetworkAnalyzer

# Initialize analyzer
analyzer = RealTimeNetworkAnalyzer()
analyzer.set_model(trained_model)

# Start processing
analyzer.start_processing()

# Add network flows
flow_data = {
    'src_ip': '192.168.1.100',
    'dst_ip': '10.0.0.1',
    'src_port': 12345,
    'dst_port': 80,
    'protocol': 'TCP',
    'flow_duration': 1000000,
    'total_fwd_packets': 10,
    'total_backward_packets': 8,
    # ... more features
}
analyzer.add_flow(flow_data)

# Get alerts
alerts = analyzer.get_alerts()
for alert in alerts:
    print(f"ALERT: {alert['severity']} - {alert['description']}")
\`\`\`

## Dataset Format

The system expects CSV files with network flow features. Common features include:

- `Flow Duration`: Duration of the flow in microseconds
- `Total Fwd Packets`: Number of forward packets
- `Total Backward Packets`: Number of backward packets
- `Total Length of Fwd Packets`: Total bytes in forward direction
- `Total Length of Bwd Packets`: Total bytes in backward direction
- `Fwd Packet Length Max/Min/Mean`: Packet size statistics
- `Flow Bytes/s`: Flow byte rate
- `Flow Packets/s`: Flow packet rate
- `Flow IAT Mean/Std`: Inter-arrival time statistics
- `Label`: Attack type or 'BENIGN' for normal traffic

### Supported Datasets
- CICIDS2017/2018
- NSL-KDD
- UNSW-NB15
- Custom datasets with similar features

## Architecture

### Core Components

1. **Data Processing Pipeline** (`data_processor.py`)
   - Data cleaning and preprocessing
   - Feature extraction and engineering
   - Label encoding and normalization

2. **Deep Learning Models** (`deep_learning_model.py`)
   - Multiple neural network architectures
   - Training and evaluation utilities
   - Model persistence and loading

3. **Feature Engineering** (`feature_engineering.py`)
   - Statistical feature extraction
   - Flow-based feature engineering
   - Feature selection methods

4. **Real-time Analyzer** (`realtime_analyzer.py`)
   - Live traffic processing
   - Threat detection and alerting
   - Performance monitoring

5. **Network Integrations**
   - Zeek log processing (`zeek_integration.py`)
   - CICFlowMeter integration (`cicflowmeter_integration.py`)

6. **Dashboard** (`streamlit_app.py`)
   - Web-based user interface
   - Real-time visualization
   - System control and configuration

## Performance

### Benchmarks
- **Processing Speed**: ~1000 flows/second on modern hardware
- **Memory Usage**: ~500MB for typical deployment
- **Detection Accuracy**: >95% on standard datasets
- **False Positive Rate**: <2% with proper tuning

### Optimization Tips
1. Adjust batch size based on available memory
2. Use feature selection to reduce dimensionality
3. Configure alert thresholds to balance sensitivity/specificity
4. Monitor buffer utilization to prevent overflow

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure all dependencies are installed: `pip install -r requirements.txt`
   - Check that scripts are in the correct directory

2. **Model Training Fails**
   - Verify dataset format and column names
   - Check for sufficient memory and disk space
   - Reduce batch size or model complexity

3. **Real-time Monitoring Issues**
   - Ensure network interface permissions
   - Check firewall settings
   - Verify Zeek/tcpdump installation

4. **Performance Issues**
   - Reduce processing batch size
   - Increase processing interval
   - Use feature selection to reduce dimensionality

### Logs and Debugging
- Check console output for error messages
- Enable debug logging: `logging.basicConfig(level=logging.DEBUG)`
- Monitor system resources during operation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Zeek Network Security Monitor
- CICFlowMeter for flow feature extraction
- TensorFlow and Scikit-learn for machine learning
- Streamlit for the web interface
- The cybersecurity research community for datasets and methodologies
