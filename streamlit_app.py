import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
import threading
import queue
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import sys
import os

# Add scripts directory to path
sys.path.append('scripts')

# Import our custom modules
try:
    from realtime_analyzer import RealTimeNetworkAnalyzer
    from data_processor import NetworkDataProcessor
    from deep_learning_model import DeepIDSModel
    from feature_engineering import NetworkFeatureEngineer
    from zeek_integration import ZeekIntegration
    from cicflowmeter_integration import CICFlowMeterIntegration
except ImportError as e:
    st.error(f"Error importing modules: {str(e)}")
    st.stop()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        padding: 1rem;
        background: linear-gradient(90deg, #f0f2f6, #ffffff);
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }

    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #1f77b4;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
    }

    .alert-critical {
        background: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }

    .alert-high {
        background: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }

    .alert-medium {
        background: #f3e5f5;
        border-left: 4px solid #9c27b0;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }

    .alert-low {
        background: #e8f5e8;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }

    .status-running {
        color: #4caf50;
        font-weight: bold;
    }

    .status-stopped {
        color: #f44336;
        font-weight: bold;
    }

    .sidebar-section {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)


# Initialize session state
def initialize_session_state():
    """Initialize Streamlit session state variables"""
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = None

    if 'model' not in st.session_state:
        st.session_state.model = None

    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False

    if 'alerts' not in st.session_state:
        st.session_state.alerts = []

    if 'flow_history' not in st.session_state:
        st.session_state.flow_history = []

    if 'stats_history' not in st.session_state:
        st.session_state.stats_history = []

    if 'zeek_integration' not in st.session_state:
        st.session_state.zeek_integration = None

    if 'cicflow_integration' not in st.session_state:
        st.session_state.cicflow_integration = None


# Main dashboard functions
def create_main_header():
    """Create the main dashboard header"""
    st.markdown('<div class="main-header">🛡️ Network Intrusion Detection System</div>',
                unsafe_allow_html=True)


def create_sidebar():
    """Create the sidebar with navigation and controls"""
    st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.sidebar.title("🛡️ IDS Control Panel")
    st.sidebar.markdown('</div>', unsafe_allow_html=True)

    # Navigation
    st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.sidebar.subheader("📊 Navigation")
    page = st.sidebar.selectbox(
        "Select Page",
        ["Real-time Monitoring", "Alert Management", "Model Training",
         "System Configuration", "Historical Analysis", "Data Processing"]
    )
    st.sidebar.markdown('</div>', unsafe_allow_html=True)

    # System Status
    st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.sidebar.subheader("🔧 System Status")

    if st.session_state.monitoring_active:
        st.sidebar.markdown('<span class="status-running">🟢 MONITORING ACTIVE</span>',
                            unsafe_allow_html=True)
    else:
        st.sidebar.markdown('<span class="status-stopped">🔴 MONITORING STOPPED</span>',
                            unsafe_allow_html=True)

    # Model Status
    if st.session_state.model and st.session_state.model.is_trained:
        st.sidebar.success("✅ Model Ready")
    else:
        st.sidebar.warning("⚠️ No Model Loaded")

    st.sidebar.markdown('</div>', unsafe_allow_html=True)

    # Quick Controls
    st.sidebar.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
    st.sidebar.subheader("⚡ Quick Controls")

    col1, col2 = st.sidebar.columns(2)

    with col1:
        if st.button("🚀 Start Monitoring", disabled=st.session_state.monitoring_active):
            start_monitoring()

    with col2:
        if st.button("⏹️ Stop Monitoring", disabled=not st.session_state.monitoring_active):
            stop_monitoring()

    if st.button("🔄 Reset System"):
        reset_system()

    st.sidebar.markdown('</div>', unsafe_allow_html=True)

    return page


def start_monitoring():
    """Start the real-time monitoring system"""
    try:
        if not st.session_state.analyzer:
            st.session_state.analyzer = RealTimeNetworkAnalyzer(buffer_size=1000)

        if st.session_state.model:
            st.session_state.analyzer.set_model(st.session_state.model)

        st.session_state.analyzer.start_processing()
        st.session_state.monitoring_active = True

        # Connect to available traffic sources
        try:
            # Try to connect to Zeek if available
            zeek_source = st.session_state.analyzer.connect_to_traffic_source('zeek')
            st.sidebar.success("✅ Connected to Zeek traffic source")
        except Exception as e:
            st.sidebar.warning(f"⚠️ Zeek not available: {str(e)}")

        try:
            # Try to connect to CICFlowMeter if available
            cicflow_source = st.session_state.analyzer.connect_to_traffic_source('cicflowmeter')
            st.sidebar.success("✅ Connected to CICFlowMeter traffic source")
        except Exception as e:
            st.sidebar.warning(f"⚠️ CICFlowMeter not available: {str(e)}")

        st.sidebar.success("✅ Monitoring started!")

    except Exception as e:
        st.sidebar.error(f"❌ Error starting monitoring: {str(e)}")


def stop_monitoring():
    """Stop the real-time monitoring system"""
    try:
        if st.session_state.analyzer:
            st.session_state.analyzer.stop_processing()

        st.session_state.monitoring_active = False
        st.sidebar.success("✅ Monitoring stopped!")

    except Exception as e:
        st.sidebar.error(f"❌ Error stopping monitoring: {str(e)}")


def reset_system():
    """Reset the entire system"""
    try:
        if st.session_state.analyzer:
            st.session_state.analyzer.stop_processing()

        # Clear session state
        for key in ['analyzer', 'model', 'alerts', 'flow_history', 'stats_history']:
            if key in st.session_state:
                del st.session_state[key]

        st.session_state.monitoring_active = False
        initialize_session_state()

        st.sidebar.success("✅ System reset!")
        st.rerun()

    except Exception as e:
        st.sidebar.error(f"❌ Error resetting system: {str(e)}")


def real_time_monitoring_page():
    """Real-time monitoring dashboard page"""
    st.header("📊 Real-time Network Monitoring")

    # Create placeholder containers for real-time updates
    metrics_container = st.container()
    charts_container = st.container()
    alerts_container = st.container()

    # Auto-refresh every 2 seconds
    placeholder = st.empty()

    if st.session_state.monitoring_active and st.session_state.analyzer:
        # Get current statistics
        stats = st.session_state.analyzer.get_statistics()
        st.session_state.stats_history.append({
            'timestamp': datetime.now(),
            **stats
        })

        # Keep only last 100 entries
        if len(st.session_state.stats_history) > 100:
            st.session_state.stats_history = st.session_state.stats_history[-100:]

        # Get recent alerts
        new_alerts = st.session_state.analyzer.get_alerts(max_alerts=50)
        st.session_state.alerts.extend(new_alerts)

        # Keep only last 200 alerts
        if len(st.session_state.alerts) > 200:
            st.session_state.alerts = st.session_state.alerts[-200:]

        with metrics_container:
            display_metrics(stats)

        with charts_container:
            display_charts(st.session_state.stats_history)

        with alerts_container:
            display_recent_alerts(st.session_state.alerts[-10:])  # Show last 10 alerts

        # Auto-refresh
        time.sleep(2)
        st.rerun()

    else:
        st.info("🔄 Start monitoring to see real-time data")

        # Show demo data
        if st.button("📊 Show Demo Data"):
            display_demo_data()


def display_metrics(stats):
    """Display key metrics"""
    st.subheader("📈 Key Metrics")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Total Flows",
            value=f"{stats['total_flows_processed']:,}",
            delta=f"+{stats.get('flows_per_second', 0):.1f}/sec"
        )

    with col2:
        st.metric(
            label="Malicious Flows",
            value=f"{stats['malicious_flows']:,}",
            delta=f"{stats['detection_rate']:.1f}%"
        )

    with col3:
        st.metric(
            label="Active Alerts",
            value=f"{stats['alerts_generated']:,}",
            delta=f"{stats['alert_rate']:.1f}%"
        )

    with col4:
        st.metric(
            label="Processing Time",
            value=f"{stats['avg_processing_time_ms']:.1f}ms",
            delta=f"Buffer: {stats['buffer_size']}"
        )


def display_charts(stats_history):
    """Display real-time charts"""
    if not stats_history:
        return

    st.subheader("📊 Real-time Charts")

    # Convert to DataFrame
    df_stats = pd.DataFrame(stats_history)

    col1, col2 = st.columns(2)

    with col1:
        # Flow rate over time
        fig_flows = px.line(
            df_stats,
            x='timestamp',
            y=['total_flows_processed', 'malicious_flows', 'benign_flows'],
            title="Network Flow Analysis",
            labels={'value': 'Flow Count', 'timestamp': 'Time'}
        )
        fig_flows.update_layout(height=400)
        st.plotly_chart(fig_flows, use_container_width=True)

    with col2:
        # Detection rate over time
        fig_detection = px.line(
            df_stats,
            x='timestamp',
            y=['detection_rate', 'alert_rate'],
            title="Detection & Alert Rates",
            labels={'value': 'Rate (%)', 'timestamp': 'Time'}
        )
        fig_detection.update_layout(height=400)
        st.plotly_chart(fig_detection, use_container_width=True)

    # Performance metrics
    col3, col4 = st.columns(2)

    with col3:
        # Processing time
        fig_perf = px.line(
            df_stats,
            x='timestamp',
            y='avg_processing_time_ms',
            title="Processing Performance",
            labels={'avg_processing_time_ms': 'Processing Time (ms)', 'timestamp': 'Time'}
        )
        fig_perf.update_layout(height=300)
        st.plotly_chart(fig_perf, use_container_width=True)

    with col4:
        # Buffer utilization
        fig_buffer = px.line(
            df_stats,
            x='timestamp',
            y='buffer_size',
            title="Buffer Utilization",
            labels={'buffer_size': 'Buffer Size', 'timestamp': 'Time'}
        )
        fig_buffer.update_layout(height=300)
        st.plotly_chart(fig_buffer, use_container_width=True)


def display_recent_alerts(alerts):
    """Display recent security alerts"""
    st.subheader("🚨 Recent Security Alerts")

    if not alerts:
        st.info("No recent alerts")
        return

    for alert in reversed(alerts):  # Show newest first
        severity = alert.get('severity', 'LOW')
        css_class = f"alert-{severity.lower()}"

        st.markdown(f"""
        <div class="{css_class}">
            <strong>🚨 {severity} ALERT</strong> - {alert.get('timestamp', 'Unknown time')}<br>
            <strong>Flow:</strong> {alert.get('flow_id', 'Unknown')}<br>
            <strong>Confidence:</strong> {alert.get('confidence', 0):.1%}<br>
            <strong>Description:</strong> {alert.get('description', 'No description')}<br>
            <strong>Action:</strong> {alert.get('recommended_action', 'No action specified')}
        </div>
        """, unsafe_allow_html=True)


def alert_management_page():
    """Alert management page"""
    st.header("🚨 Alert Management")

    if not st.session_state.alerts:
        st.info("No alerts to display. Start monitoring to generate alerts.")
        return

    # Alert statistics
    st.subheader("📊 Alert Statistics")

    df_alerts = pd.DataFrame(st.session_state.alerts)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Alerts", len(df_alerts))

    with col2:
        critical_count = len(df_alerts[df_alerts['severity'] == 'CRITICAL'])
        st.metric("Critical Alerts", critical_count)

    with col3:
        high_count = len(df_alerts[df_alerts['severity'] == 'HIGH'])
        st.metric("High Priority", high_count)

    with col4:
        avg_confidence = df_alerts['confidence'].mean()
        st.metric("Avg Confidence", f"{avg_confidence:.1%}")

    # Alert severity distribution
    col1, col2 = st.columns(2)

    with col1:
        severity_counts = df_alerts['severity'].value_counts()
        fig_severity = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            title="Alert Severity Distribution"
        )
        st.plotly_chart(fig_severity, use_container_width=True)

    with col2:
        # Alerts over time
        df_alerts['timestamp'] = pd.to_datetime(df_alerts['timestamp'])
        alerts_over_time = df_alerts.groupby(df_alerts['timestamp'].dt.floor('min')).size()

        fig_timeline = px.line(
            x=alerts_over_time.index,
            y=alerts_over_time.values,
            title="Alerts Over Time",
            labels={'x': 'Time', 'y': 'Alert Count'}
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

    # Alert details table
    st.subheader("📋 Alert Details")

    # Filter options
    col1, col2, col3 = st.columns(3)

    with col1:
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All"] + list(df_alerts['severity'].unique())
        )

    with col2:
        confidence_threshold = st.slider(
            "Minimum Confidence",
            0.0, 1.0, 0.0, 0.1
        )

    with col3:
        max_alerts = st.number_input(
            "Max Alerts to Show",
            1, 1000, 50
        )

    # Apply filters
    filtered_alerts = df_alerts.copy()

    if severity_filter != "All":
        filtered_alerts = filtered_alerts[filtered_alerts['severity'] == severity_filter]

    filtered_alerts = filtered_alerts[filtered_alerts['confidence'] >= confidence_threshold]
    filtered_alerts = filtered_alerts.head(max_alerts)

    # Display filtered alerts
    st.dataframe(
        filtered_alerts[['timestamp', 'severity', 'flow_id', 'confidence', 'description', 'recommended_action']],
        use_container_width=True
    )

    # Export alerts
    if st.button("📥 Export Alerts to CSV"):
        csv = filtered_alerts.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"ids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )


def model_training_page():
    """Model training and evaluation page"""
    st.header("🤖 Model Training & Evaluation")

    # Model configuration
    st.subheader("⚙️ Model Configuration")

    col1, col2 = st.columns(2)

    with col1:
        model_type = st.selectbox(
            "Model Type",
            ["dnn", "cnn", "lstm", "hybrid", "autoencoder"]
        )

        learning_rate = st.number_input(
            "Learning Rate",
            0.0001, 0.1, 0.001, 0.0001,
            format="%.4f"
        )

    with col2:
        epochs = st.number_input("Epochs", 1, 200, 50)
        batch_size = st.number_input("Batch Size", 16, 512, 128)

    # Dataset upload
    st.subheader("📁 Dataset Upload")

    uploaded_file = st.file_uploader(
        "Upload training dataset (CSV)",
        type=['csv'],
        help="Upload a CSV file with network flow features and labels"
    )

    if uploaded_file is not None:
        try:
            # Load and preview dataset
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

            # Show dataset preview
            st.subheader("📊 Dataset Preview")
            st.dataframe(df.head(), use_container_width=True)

            # Dataset statistics
            col1, col2 = st.columns(2)

            with col1:
                st.write("**Dataset Info:**")
                st.write(f"- Rows: {df.shape[0]:,}")
                st.write(f"- Columns: {df.shape[1]:,}")
                st.write(f"- Missing values: {df.isnull().sum().sum():,}")

            with col2:
                if 'Label' in df.columns:
                    label_dist = df['Label'].value_counts()
                    st.write("**Label Distribution:**")
                    for label, count in label_dist.items():
                        st.write(f"- {label}: {count:,}")

            # Train model button
            if st.button("🚀 Train Model"):
                train_model_with_data(df, model_type, learning_rate, epochs, batch_size)

        except Exception as e:
            st.error(f"❌ Error loading dataset: {str(e)}")

    else:
        # Generate sample data for demo
        if st.button("📊 Generate Sample Data for Demo"):
            generate_and_train_demo_model(model_type, learning_rate, epochs, batch_size)

    # Model evaluation
    if st.session_state.model and st.session_state.model.is_trained:
        st.subheader("📈 Model Performance")
        display_model_performance()


def train_model_with_data(df, model_type, learning_rate, epochs, batch_size):
    """Train model with uploaded data"""
    try:
        with st.spinner("🔄 Training model..."):
            # Initialize data processor
            processor = NetworkDataProcessor()

            if 'Label' not in df.columns:
                st.error("❌ Dataset must contain a 'Label' column for training")
                return

            # Process data with proper error handling
            df_processed = processor.clean_dataset(df)
            df_processed = processor.extract_features(df_processed)

            if 'Binary_Label' not in df_processed.columns:
                df_processed = processor.encode_labels(df_processed)

            df_processed = processor.normalize_features(df_processed, fit=True)

            if 'Binary_Label' not in df_processed.columns:
                st.error("❌ Failed to create Binary_Label column. Check your dataset format.")
                return

            # Prepare training data
            X_train, X_test, y_train, y_test = processor.prepare_training_data(df_processed)

            # Initialize and train model
            model = DeepIDSModel(input_dim=X_train.shape[1], model_type=model_type)
            model.build_model()
            model.compile_model(learning_rate=learning_rate)

            # Train model
            history = model.train_model(
                X_train, y_train,
                X_test, y_test,
                epochs=epochs,
                batch_size=batch_size
            )

            # Evaluate model
            results = model.evaluate_model(X_test, y_test)

            # Store in session state
            st.session_state.model = model
            st.session_state.training_history = history
            st.session_state.evaluation_results = results

            st.success(f"✅ Model trained successfully! Accuracy: {results['test_accuracy']:.4f}")

    except Exception as e:
        st.error(f"❌ Error training model: {str(e)}")
        if "Binary_Label" in str(e):
            st.info("💡 Make sure your dataset has a 'Label' column with attack types or 'BENIGN'/'NORMAL' labels")


def generate_and_train_demo_model(model_type, learning_rate, epochs, batch_size):
    """Generate sample data and train demo model"""
    try:
        with st.spinner("🔄 Generating sample data and training model..."):
            # Generate sample data
            np.random.seed(42)
            n_samples = 2000
            n_features = 25

            X = np.random.randn(n_samples, n_features)
            y = np.random.randint(0, 2, n_samples)

            # Split data
            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )

            # Initialize and train model
            model = DeepIDSModel(input_dim=n_features, model_type=model_type)
            model.build_model()
            model.compile_model(learning_rate=learning_rate)

            # Train model
            history = model.train_model(
                X_train, y_train,
                X_test, y_test,
                epochs=min(epochs, 20),  # Limit epochs for demo
                batch_size=batch_size,
                early_stopping=True
            )

            # Evaluate model
            results = model.evaluate_model(X_test, y_test)

            # Store in session_state
            st.session_state.model = model
            st.session_state.training_history = history
            st.session_state.evaluation_results = results

            st.success(f"✅ Demo model trained! Accuracy: {results['test_accuracy']:.4f}")

    except Exception as e:
        st.error(f"❌ Error training demo model: {str(e)}")


def display_model_performance():
    """Display model performance metrics and charts"""
    if 'evaluation_results' not in st.session_state:
        st.info("No evaluation results available")
        return

    results = st.session_state.evaluation_results

    # Performance metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Accuracy", f"{results['test_accuracy']:.4f}")

    with col2:
        st.metric("ROC-AUC", f"{results['roc_auc']:.4f}")

    with col3:
        precision = results['classification_report']['1']['precision']
        st.metric("Precision", f"{precision:.4f}")

    with col4:
        recall = results['classification_report']['1']['recall']
        st.metric("Recall", f"{recall:.4f}")

    # Training history
    if 'training_history' in st.session_state:
        history = st.session_state.training_history

        col1, col2 = st.columns(2)

        with col1:
            # Loss curves
            fig_loss = go.Figure()
            fig_loss.add_trace(go.Scatter(
                y=history['loss'],
                name='Training Loss',
                mode='lines'
            ))
            if 'val_loss' in history:
                fig_loss.add_trace(go.Scatter(
                    y=history['val_loss'],
                    name='Validation Loss',
                    mode='lines'
                ))
            fig_loss.update_layout(title="Training Loss", xaxis_title="Epoch", yaxis_title="Loss")
            st.plotly_chart(fig_loss, use_container_width=True)

        with col2:
            # Accuracy curves
            fig_acc = go.Figure()
            fig_acc.add_trace(go.Scatter(
                y=history['accuracy'],
                name='Training Accuracy',
                mode='lines'
            ))
            if 'val_accuracy' in history:
                fig_acc.add_trace(go.Scatter(
                    y=history['val_accuracy'],
                    name='Validation Accuracy',
                    mode='lines'
                ))
            fig_acc.update_layout(title="Training Accuracy", xaxis_title="Epoch", yaxis_title="Accuracy")
            st.plotly_chart(fig_acc, use_container_width=True)

    # Confusion matrix
    if 'confusion_matrix' in results:
        cm = np.array(results['confusion_matrix'])

        fig_cm = px.imshow(
            cm,
            text_auto=True,
            aspect="auto",
            title="Confusion Matrix",
            labels=dict(x="Predicted", y="Actual", color="Count")
        )
        st.plotly_chart(fig_cm, use_container_width=True)


def system_configuration_page():
    """System configuration page"""
    st.header("⚙️ System Configuration")

    # Real-time analyzer settings
    st.subheader("🔧 Real-time Analyzer Settings")

    col1, col2 = st.columns(2)

    with col1:
        alert_threshold = st.slider(
            "Alert Threshold",
            0.0, 1.0, 0.7, 0.05,
            help="Confidence threshold for generating alerts"
        )

        batch_size = st.number_input(
            "Processing Batch Size",
            10, 500, 50,
            help="Number of flows to process in each batch"
        )

    with col2:
        processing_interval = st.number_input(
            "Processing Interval (seconds)",
            0.1, 10.0, 1.0, 0.1,
            help="Time interval between processing batches"
        )

        max_alerts_per_minute = st.number_input(
            "Max Alerts per Minute",
            1, 1000, 100,
            help="Rate limiting for alert generation"
        )

    # Integration settings
    st.subheader("🔌 Integration Settings")

    tab1, tab2 = st.tabs(["Zeek Integration", "CICFlowMeter Integration"])

    with tab1:
        st.write("**Zeek Configuration**")

        zeek_path = st.text_input(
            "Zeek Binary Path",
            "/usr/local/zeek/bin/zeek",
            help="Path to Zeek binary"
        )

        zeek_log_dir = st.text_input(
            "Zeek Log Directory",
            "./zeek_logs",
            help="Directory for Zeek log files"
        )

        network_interface = st.text_input(
            "Network Interface",
            "eth0",
            help="Network interface for monitoring"
        )

        if st.button("🔧 Initialize Zeek Integration"):
            try:
                zeek_integration = ZeekIntegration(
                    zeek_path=zeek_path,
                    log_dir=zeek_log_dir
                )
                st.session_state.zeek_integration = zeek_integration
                st.success("✅ Zeek integration initialized")
            except Exception as e:
                st.error(f"❌ Error initializing Zeek: {str(e)}")

    with tab2:
        st.write("**CICFlowMeter Configuration**")

        cicflow_output_dir = st.text_input(
            "Output Directory",
            "./cicflow_output",
            help="Directory for CICFlowMeter output"
        )

        if st.button("🔧 Initialize CICFlowMeter Integration"):
            try:
                cicflow_integration = CICFlowMeterIntegration(
                    output_dir=cicflow_output_dir
                )
                st.session_state.cicflow_integration = cicflow_integration
                st.success("✅ CICFlowMeter integration initialized")
            except Exception as e:
                st.error(f"❌ Error initializing CICFlowMeter: {str(e)}")

    # Apply configuration
    if st.button("💾 Apply Configuration"):
        apply_configuration(alert_threshold, batch_size, processing_interval, max_alerts_per_minute)


def apply_configuration(alert_threshold, batch_size, processing_interval, max_alerts_per_minute):
    """Apply configuration changes"""
    try:
        if st.session_state.analyzer:
            st.session_state.analyzer.config.update({
                'alert_threshold': alert_threshold,
                'batch_size': batch_size,
                'processing_interval': processing_interval,
                'max_alerts_per_minute': max_alerts_per_minute
            })

        st.success("✅ Configuration applied successfully")

    except Exception as e:
        st.error(f"❌ Error applying configuration: {str(e)}")


def historical_analysis_page():
    """Historical analysis and reporting page"""
    st.header("📊 Historical Analysis")

    if not st.session_state.stats_history:
        st.info("No historical data available. Start monitoring to collect data.")
        return

    # Time range selection
    st.subheader("📅 Time Range Analysis")

    df_history = pd.DataFrame(st.session_state.stats_history)
    df_history['timestamp'] = pd.to_datetime(df_history['timestamp'])

    col1, col2 = st.columns(2)

    with col1:
        start_time = st.date_input(
            "Start Time",
            value=df_history['timestamp'].min().date()
        )

    with col2:
        end_time = st.date_input(
            "End Time",
            value=df_history['timestamp'].max().date()
        )

    # Filter data by time range
    mask = (df_history['timestamp'].dt.date >= start_time) & (df_history['timestamp'].dt.date <= end_time)
    filtered_data = df_history.loc[mask]

    if filtered_data.empty:
        st.warning("No data available for selected time range")
        return

    # Summary statistics
    st.subheader("📈 Summary Statistics")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        total_flows = filtered_data['total_flows_processed'].max()
        st.metric("Total Flows", f"{total_flows:,}")

    with col2:
        total_malicious = filtered_data['malicious_flows'].max()
        st.metric("Malicious Flows", f"{total_malicious:,}")

    with col3:
        avg_detection_rate = filtered_data['detection_rate'].mean()
        st.metric("Avg Detection Rate", f"{avg_detection_rate:.1f}%")

    with col4:
        total_alerts = filtered_data['alerts_generated'].max()
        st.metric("Total Alerts", f"{total_alerts:,}")

    # Detailed charts
    st.subheader("📊 Detailed Analysis")

    # Traffic patterns
    fig_traffic = px.line(
        filtered_data,
        x='timestamp',
        y=['total_flows_processed', 'malicious_flows', 'benign_flows'],
        title="Traffic Patterns Over Time"
    )
    st.plotly_chart(fig_traffic, use_container_width=True)

    # Performance analysis
    col1, col2 = st.columns(2)

    with col1:
        fig_perf = px.scatter(
            filtered_data,
            x='total_flows_processed',
            y='avg_processing_time_ms',
            title="Processing Performance vs Load",
            labels={'avg_processing_time_ms': 'Processing Time (ms)', 'total_flows_processed': 'Total Flows'}
        )
        st.plotly_chart(fig_perf, use_container_width=True)

    with col2:
        fig_detection = px.histogram(
            filtered_data,
            x='detection_rate',
            title="Detection Rate Distribution",
            labels={'detection_rate': 'Detection Rate (%)', 'count': 'Frequency'}
        )
        st.plotly_chart(fig_detection, use_container_width=True)

    # Export historical data
    if st.button("📥 Export Historical Data"):
        csv = filtered_data.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"ids_history_{start_time}_{end_time}.csv",
            mime="text/csv"
        )


def data_processing_page():
    """Data processing and feature engineering page"""
    st.header("🔧 Data Processing & Feature Engineering")

    # File upload for processing
    st.subheader("📁 Upload Data for Processing")

    uploaded_file = st.file_uploader(
        "Upload network traffic data (CSV)",
        type=['csv'],
        help="Upload raw network traffic data for processing and feature extraction"
    )

    if uploaded_file is not None:
        try:
            # Load data
            df_raw = pd.read_csv(uploaded_file)
            st.success(f"✅ Data loaded: {df_raw.shape[0]} rows, {df_raw.shape[1]} columns")

            # Show raw data preview
            st.subheader("📊 Raw Data Preview")
            st.dataframe(df_raw.head(), use_container_width=True)

            # Processing options
            st.subheader("⚙️ Processing Options")

            col1, col2 = st.columns(2)

            with col1:
                clean_data = st.checkbox("Clean Data", value=True)
                extract_features = st.checkbox("Extract Features", value=True)
                normalize_features = st.checkbox("Normalize Features", value=True)

            with col2:
                encode_labels = st.checkbox("Encode Labels", value=True)
                feature_selection = st.checkbox("Feature Selection", value=False)

                if feature_selection:
                    selection_method = st.selectbox(
                        "Selection Method",
                        ["univariate", "mutual_info", "rf_importance"]
                    )
                    n_features = st.number_input("Number of Features", 10, 100, 50)

            # Process data
            if st.button("🚀 Process Data"):
                process_uploaded_data(df_raw, clean_data, extract_features, normalize_features,
                                      encode_labels, feature_selection,
                                      selection_method if feature_selection else None,
                                      n_features if feature_selection else None)

        except Exception as e:
            st.error(f"❌ Error loading data: {str(e)}")


def process_uploaded_data(df_raw, clean_data, extract_features, normalize_features,
                          encode_labels, feature_selection, selection_method, n_features):
    """Process uploaded data with selected options"""
    try:
        with st.spinner("🔄 Processing data..."):
            # Initialize processors
            data_processor = NetworkDataProcessor()
            feature_engineer = NetworkFeatureEngineer()

            df_processed = df_raw.copy()
            processing_steps = []

            # Clean data
            if clean_data:
                df_processed = data_processor.clean_dataset(df_processed)
                processing_steps.append(f"✅ Data cleaned: {df_processed.shape}")

            # Extract features
            if extract_features:
                df_processed = data_processor.extract_features(df_processed)
                df_processed = feature_engineer.extract_flow_features(df_processed)
                processing_steps.append(f"✅ Features extracted: {df_processed.shape}")

            # Encode labels
            if encode_labels and 'Label' in df_processed.columns:
                df_processed = data_processor.encode_labels(df_processed)
                processing_steps.append("✅ Labels encoded")

            # Normalize features
            if normalize_features:
                df_processed = data_processor.normalize_features(df_processed, fit=True)
                processing_steps.append("✅ Features normalized")

            # Feature selection
            if feature_selection:
                if 'Binary_Label' not in df_processed.columns:
                    st.warning(
                        "⚠️ Binary_Label column not found. Skipping feature selection. Make sure to encode labels first.")
                else:
                    numeric_cols = df_processed.select_dtypes(include=[np.number]).columns.tolist()
                    feature_cols = [col for col in numeric_cols if
                                    col not in ['Label', 'Binary_Label', 'Original_Label']]

                    if feature_cols:
                        X = df_processed[feature_cols].values
                        y = df_processed['Binary_Label'].values

                        if selection_method == "univariate":
                            X_selected, selected_indices = feature_engineer.select_features_univariate(X, y,
                                                                                                       k=n_features)
                        elif selection_method == "mutual_info":
                            X_selected, selected_indices = feature_engineer.select_features_mutual_info(X, y,
                                                                                                        k=n_features)
                        else:  # rf_importance
                            X_selected, selected_indices = feature_engineer.select_features_importance(X, y,
                                                                                                       k=n_features)

                        selected_features = [feature_cols[i] for i in selected_indices]
                        df_processed = df_processed[selected_features + ['Label', 'Binary_Label', 'Original_Label']]
                        processing_steps.append(f"✅ Feature selection: {len(selected_features)} features selected")
                    else:
                        st.warning("⚠️ No numeric feature columns found for selection")

            # Display results
            st.success("✅ Data processing completed!")

            # Show processing steps
            st.subheader("📋 Processing Steps")
            for step in processing_steps:
                st.write(step)

            # Show processed data
            st.subheader("📊 Processed Data Preview")
            st.dataframe(df_processed.head(), use_container_width=True)

            # Data statistics
            col1, col2 = st.columns(2)

            with col1:
                st.write("**Dataset Statistics:**")
                st.write(f"- Original shape: {df_raw.shape}")
                st.write(f"- Processed shape: {df_processed.shape}")
                st.write(f"- Missing values: {df_processed.isnull().sum().sum()}")

            with col2:
                if 'Binary_Label' in df_processed.columns:
                    label_dist = df_processed['Binary_Label'].value_counts()
                    st.write("**Label Distribution:**")
                    st.write(f"- Benign (0): {label_dist.get(0, 0):,}")
                    st.write(f"- Malicious (1): {label_dist.get(1, 0):,}")

            # Download processed data
            csv = df_processed.to_csv(index=False)
            st.download_button(
                label="📥 Download Processed Data",
                data=csv,
                file_name=f"processed_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

    except Exception as e:
        st.error(f"❌ Error processing data: {str(e)}")


def display_demo_data():
    """Display demo data for testing"""
    st.subheader("📊 Demo Data Visualization")

    # Generate sample data
    np.random.seed(42)
    dates = pd.date_range(start='2024-01-01', periods=100, freq='H')

    demo_data = {
        'timestamp': dates,
        'total_flows': np.cumsum(np.random.poisson(50, 100)),
        'malicious_flows': np.cumsum(np.random.poisson(5, 100)),
        'alerts': np.cumsum(np.random.poisson(2, 100)),
        'processing_time': np.random.normal(15, 3, 100)
    }

    df_demo = pd.DataFrame(demo_data)
    df_demo['benign_flows'] = df_demo['total_flows'] - df_demo['malicious_flows']
    df_demo['detection_rate'] = (df_demo['malicious_flows'] / df_demo['total_flows']) * 100

    # Display charts
    col1, col2 = st.columns(2)

    with col1:
        fig_flows = px.line(
            df_demo,
            x='timestamp',
            y=['total_flows', 'malicious_flows', 'benign_flows'],
            title="Demo: Network Flow Analysis"
        )
        st.plotly_chart(fig_flows, use_container_width=True)

    with col2:
        fig_detection = px.line(
            df_demo,
            x='timestamp',
            y='detection_rate',
            title="Demo: Detection Rate Over Time"
        )
        st.plotly_chart(fig_detection, use_container_width=True)


# Main application
def main():
    """Main application function"""
    # Initialize session state
    initialize_session_state()

    # Create main header
    create_main_header()

    # Create sidebar and get selected page
    selected_page = create_sidebar()

    # Display selected page
    if selected_page == "Real-time Monitoring":
        real_time_monitoring_page()
    elif selected_page == "Alert Management":
        alert_management_page()
    elif selected_page == "Model Training":
        model_training_page()
    elif selected_page == "System Configuration":
        system_configuration_page()
    elif selected_page == "Historical Analysis":
        historical_analysis_page()
    elif selected_page == "Data Processing":
        data_processing_page()


if __name__ == "__main__":
    main()
