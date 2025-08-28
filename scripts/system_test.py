#!/usr/bin/env python3
"""
Comprehensive system test for the Network Intrusion Detection System
Tests all components to ensure they work together properly
"""

import sys
import os
import logging
import traceback
from pathlib import Path

# Add scripts directory to path
sys.path.append(str(Path(__file__).parent))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_imports():
    """Test all required imports"""
    print("🔍 Testing imports...")

    try:
        # Core libraries
        import pandas as pd
        import numpy as np
        import matplotlib.pyplot as plt
        import seaborn as sns
        import plotly.graph_objects as go
        import streamlit as st
        import tensorflow as tf
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler

        print(f"✅ Core libraries imported successfully")
        print(f"   - Pandas: {pd.__version__}")
        print(f"   - NumPy: {np.__version__}")
        print(f"   - TensorFlow: {tf.__version__}")
        print(f"   - Streamlit: {st.__version__}")

        # Our modules
        from data_processor import NetworkDataProcessor
        from deep_learning_model import DeepIDSModel
        from feature_engineering import FeatureEngineer
        from realtime_analyzer import RealTimeNetworkAnalyzer
        from cicflowmeter_integration import CICFlowMeterIntegration
        from zeek_integration import ZeekIntegration

        print("✅ All custom modules imported successfully")
        return True

    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error during imports: {e}")
        return False


def test_data_processor():
    """Test the data processor"""
    print("\n🔍 Testing Data Processor...")

    try:
        from data_processor import NetworkDataProcessor

        processor = NetworkDataProcessor()

        # Test with sample data
        sample_data = {
            'flow_duration': [1000, 2000, 3000],
            'total_fwd_packets': [10, 20, 30],
            'total_backward_packets': [5, 15, 25],
            'label': ['BENIGN', 'DDoS', 'BENIGN']
        }

        import pandas as pd
        df = pd.DataFrame(sample_data)

        # Test preprocessing
        processed_data = processor.preprocess_data(df)
        print(f"✅ Data preprocessing successful - Shape: {processed_data.shape}")

        # Test feature extraction
        features = processor.extract_basic_features(df)
        print(f"✅ Feature extraction successful - Features: {len(features.columns)}")

        return True

    except Exception as e:
        print(f"❌ Data processor test failed: {e}")
        traceback.print_exc()
        return False


def test_deep_learning_model():
    """Test the deep learning model"""
    print("\n🔍 Testing Deep Learning Model...")

    try:
        from deep_learning_model import DeepIDSModel
        import numpy as np

        # Create sample data
        n_samples = 100
        n_features = 20
        X_train = np.random.randn(n_samples, n_features)
        y_train = np.random.randint(0, 2, n_samples)

        # Test DNN model
        model = DeepIDSModel(input_dim=n_features, model_type='dnn')
        model.build_model()
        model.compile_model()

        print("✅ DNN model built and compiled successfully")

        # Test training (minimal epochs)
        history = model.train_model(X_train, y_train, epochs=2, early_stopping=False)
        print("✅ Model training successful")

        # Test prediction
        predictions, probabilities = model.predict_batch(X_train[:5])
        print(f"✅ Model prediction successful - Sample predictions: {predictions}")

        return True

    except Exception as e:
        print(f"❌ Deep learning model test failed: {e}")
        traceback.print_exc()
        return False


def test_feature_engineering():
    """Test feature engineering"""
    print("\n🔍 Testing Feature Engineering...")

    try:
        from feature_engineering import FeatureEngineer
        import pandas as pd
        import numpy as np

        # Create sample network data
        sample_data = pd.DataFrame({
            'flow_duration': np.random.randint(100, 10000, 50),
            'total_fwd_packets': np.random.randint(1, 100, 50),
            'total_backward_packets': np.random.randint(1, 100, 50),
            'fwd_packet_length_mean': np.random.uniform(50, 1500, 50),
            'flow_bytes_s': np.random.uniform(1000, 100000, 50),
            'label': np.random.choice(['BENIGN', 'DDoS', 'PortScan'], 50)
        })

        engineer = FeatureEngineer()

        # Test statistical features
        stats_features = engineer.extract_statistical_features(sample_data)
        print(f"✅ Statistical features extracted - Shape: {stats_features.shape}")

        # Test flow features
        flow_features = engineer.extract_flow_features(sample_data)
        print(f"✅ Flow features extracted - Shape: {flow_features.shape}")

        # Test feature selection
        X = sample_data.drop('label', axis=1)
        y = sample_data['label']
        selected_features = engineer.select_features_univariate(X, y, k=3)
        print(f"✅ Feature selection successful - Selected: {len(selected_features.columns)} features")

        return True

    except Exception as e:
        print(f"❌ Feature engineering test failed: {e}")
        traceback.print_exc()
        return False


def test_cicflowmeter_integration():
    """Test CICFlowMeter integration"""
    print("\n🔍 Testing CICFlowMeter Integration...")

    try:
        from cicflowmeter_integration import CICFlowMeterIntegration

        cicflow = CICFlowMeterIntegration()

        # Test system info
        info = cicflow.get_system_info()
        print(f"✅ CICFlowMeter system info retrieved")
        print(f"   - Available interfaces: {info['available_interfaces']}")
        print(f"   - CICFlowMeter available: {info['cicflowmeter_available']}")

        # Test callback setup
        def test_callback(flow_data):
            print(f"Received flow: {flow_data.get('src_ip', 'unknown')}")

        cicflow.set_flow_callback(test_callback)
        print("✅ Flow callback set successfully")

        return True

    except Exception as e:
        print(f"❌ CICFlowMeter integration test failed: {e}")
        traceback.print_exc()
        return False


def test_zeek_integration():
    """Test Zeek integration"""
    print("\n🔍 Testing Zeek Integration...")

    try:
        from zeek_integration import ZeekIntegration

        zeek = ZeekIntegration()

        # Test system info
        info = zeek.get_system_info()
        print(f"✅ Zeek system info retrieved")
        print(f"   - Zeek available: {info['zeek_available']}")
        print(f"   - Log directory: {info['log_directory']}")

        return True

    except Exception as e:
        print(f"❌ Zeek integration test failed: {e}")
        traceback.print_exc()
        return False


def test_realtime_analyzer():
    """Test real-time analyzer"""
    print("\n🔍 Testing Real-time Analyzer...")

    try:
        from realtime_analyzer import RealTimeNetworkAnalyzer

        analyzer = RealTimeNetworkAnalyzer()

        # Test analyzer initialization
        print("✅ Real-time analyzer initialized successfully")

        # Test system info
        info = analyzer.get_system_info()
        print(f"✅ Analyzer system info retrieved")
        print(f"   - Status: {info['status']}")

        return True

    except Exception as e:
        print(f"❌ Real-time analyzer test failed: {e}")
        traceback.print_exc()
        return False


def main():
    """Run all system tests"""
    print("🛡️ Network Intrusion Detection System - Comprehensive Test")
    print("=" * 60)

    tests = [
        ("Import Test", test_imports),
        ("Data Processor Test", test_data_processor),
        ("Deep Learning Model Test", test_deep_learning_model),
        ("Feature Engineering Test", test_feature_engineering),
        ("CICFlowMeter Integration Test", test_cicflowmeter_integration),
        ("Zeek Integration Test", test_zeek_integration),
        ("Real-time Analyzer Test", test_realtime_analyzer),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                failed += 1
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            failed += 1
            print(f"❌ {test_name} FAILED with exception: {e}")

        print("-" * 40)

    print(f"\n📊 Test Results:")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success Rate: {(passed / (passed + failed) * 100):.1f}%")

    if failed == 0:
        print("\n🎉 All tests passed! System is ready for use.")
        return True
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please check the errors above.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
