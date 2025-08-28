#!/usr/bin/env python3
"""
Script to run the Network Intrusion Detection System Dashboard
"""

import subprocess
import sys
import os
from pathlib import Path

def check_requirements():
    """Check if required packages are installed"""
    try:
        import streamlit
        import pandas
        import numpy
        import plotly
        import sklearn
        import tensorflow
        print("✅ All required packages are available")
        return True
    except ImportError as e:
        print(f"❌ Missing required package: {e}")
        print("Please install requirements: pip install -r requirements.txt")
        return False

def main():
    """Main function to run the dashboard"""
    print("🛡️ Network Intrusion Detection System Dashboard")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("streamlit_app.py").exists():
        print("❌ streamlit_app.py not found in current directory")
        print("Please run this script from the project root directory")
        sys.exit(1)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Check if scripts directory exists
    if not Path("scripts").exists():
        print("❌ scripts directory not found")
        print("Please ensure all Python modules are in the scripts/ directory")
        sys.exit(1)
    
    print("🚀 Starting Streamlit dashboard...")
    print("📊 Dashboard will be available at: http://localhost:8501")
    print("🔧 Use Ctrl+C to stop the dashboard")
    print("-" * 50)
    
    try:
        # Run Streamlit app
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
            "--server.port", "8501",
            "--server.address", "localhost",
            "--browser.gatherUsageStats", "false"
        ])
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
    except Exception as e:
        print(f"❌ Error running dashboard: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
