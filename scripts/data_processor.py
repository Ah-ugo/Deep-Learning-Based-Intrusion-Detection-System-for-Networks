import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import json
import logging
from typing import Dict, List, Tuple, Optional
import warnings
import os

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkDataProcessor:
    """
    Advanced data processor for network intrusion detection datasets.
    Supports multiple dataset formats including CICFlowMeter and Zeek outputs.
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.target_column = 'Label'
        self.is_fitted = False

    def load_cicids_dataset(self, file_path: str) -> pd.DataFrame:
        """Load CICIDS2017/2018 dataset or CICFlowMeter output"""
        try:
            logger.info(f"Loading dataset from {file_path}")

            # Try different encodings and separators
            encodings = ['utf-8', 'latin-1', 'iso-8859-1']
            separators = [',', ';', '\t']

            df = None
            for encoding in encodings:
                for sep in separators:
                    try:
                        df = pd.read_csv(file_path, encoding=encoding, sep=sep, low_memory=False)
                        if df.shape[1] > 1:  # Valid dataframe
                            break
                    except:
                        continue
                if df is not None and df.shape[1] > 1:
                    break

            if df is None:
                raise ValueError("Could not load dataset with any encoding/separator combination")

            logger.info(f"Dataset loaded successfully: {df.shape}")
            return df

        except Exception as e:
            logger.error(f"Error loading dataset: {str(e)}")
            raise

    def load_zeek_logs(self, log_files: List[str]) -> pd.DataFrame:
        """Load and parse Zeek log files"""
        try:
            all_data = []

            for log_file in log_files:
                logger.info(f"Processing Zeek log: {log_file}")

                # Read Zeek log (TSV format)
                with open(log_file, 'r') as f:
                    lines = f.readlines()

                # Parse Zeek header
                headers = []
                data_lines = []

                for line in lines:
                    if line.startswith('#fields'):
                        headers = line.strip().split('\t')[1:]  # Remove #fields
                    elif not line.startswith('#') and line.strip():
                        data_lines.append(line.strip().split('\t'))

                if headers and data_lines:
                    df_log = pd.DataFrame(data_lines, columns=headers)
                    all_data.append(df_log)

            if all_data:
                combined_df = pd.concat(all_data, ignore_index=True)
                logger.info(f"Zeek logs processed: {combined_df.shape}")
                return combined_df
            else:
                raise ValueError("No valid Zeek logs found")

        except Exception as e:
            logger.error(f"Error processing Zeek logs: {str(e)}")
            raise

    def clean_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and preprocess the dataset"""
        logger.info("Cleaning dataset...")

        # Make a copy
        df_clean = df.copy()

        # Handle common column name variations
        column_mapping = {
            'Label': ['Label', 'label', 'class', 'Class', 'attack_type'],
            'Flow Duration': ['Flow Duration', 'flow_duration', 'duration'],
            'Total Fwd Packets': ['Total Fwd Packets', 'fwd_packets', 'tot_fwd_pkts'],
            'Total Backward Packets': ['Total Backward Packets', 'bwd_packets', 'tot_bwd_pkts']
        }

        # Standardize column names
        for standard_name, variations in column_mapping.items():
            for variation in variations:
                if variation in df_clean.columns:
                    df_clean = df_clean.rename(columns={variation: standard_name})
                    break

        # Remove rows with all NaN values
        df_clean = df_clean.dropna(how='all')

        # Handle infinite values
        df_clean = df_clean.replace([np.inf, -np.inf], np.nan)

        # Fill NaN values with median for numeric columns
        numeric_columns = df_clean.select_dtypes(include=[np.number]).columns
        for col in numeric_columns:
            if col != self.target_column:
                df_clean[col] = df_clean[col].fillna(df_clean[col].median())

        # Remove duplicate rows
        initial_shape = df_clean.shape
        df_clean = df_clean.drop_duplicates()
        logger.info(f"Removed {initial_shape[0] - df_clean.shape[0]} duplicate rows")

        logger.info(f"Dataset cleaned: {df_clean.shape}")
        return df_clean

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract and engineer features for intrusion detection"""
        logger.info("Extracting features...")

        df_features = df.copy()

        # Identify numeric columns (excluding target)
        numeric_cols = df_features.select_dtypes(include=[np.number]).columns.tolist()
        if self.target_column in numeric_cols:
            numeric_cols.remove(self.target_column)

        # Feature engineering for network flows
        try:
            # Flow-based features
            if 'Total Fwd Packets' in df_features.columns and 'Total Backward Packets' in df_features.columns:
                df_features['Total_Packets'] = df_features['Total Fwd Packets'] + df_features['Total Backward Packets']
                df_features['Fwd_Bwd_Ratio'] = df_features['Total Fwd Packets'] / (
                            df_features['Total Backward Packets'] + 1)

            # Packet size features
            if 'Total Length of Fwd Packets' in df_features.columns and 'Total Length of Bwd Packets' in df_features.columns:
                df_features['Total_Length'] = df_features['Total Length of Fwd Packets'] + df_features[
                    'Total Length of Bwd Packets']
                df_features['Avg_Packet_Size'] = df_features['Total_Length'] / (df_features['Total_Packets'] + 1)

            # Flow duration features
            if 'Flow Duration' in df_features.columns:
                df_features['Flow_Rate'] = df_features['Total_Packets'] / (df_features['Flow Duration'] + 1)
                df_features['Bytes_per_Second'] = df_features['Total_Length'] / (df_features['Flow Duration'] + 1)

        except Exception as e:
            logger.warning(f"Feature engineering warning: {str(e)}")

        # Update numeric columns list
        numeric_cols = df_features.select_dtypes(include=[np.number]).columns.tolist()
        if self.target_column in numeric_cols:
            numeric_cols.remove(self.target_column)

        self.feature_columns = numeric_cols
        logger.info(f"Extracted {len(self.feature_columns)} features")

        return df_features

    def encode_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode target labels for classification"""
        logger.info("Encoding labels...")

        df_encoded = df.copy()

        if self.target_column not in df_encoded.columns:
            logger.error(f"Target column '{self.target_column}' not found")
            return df_encoded

        # Handle different label formats
        labels = df_encoded[self.target_column].astype(str).str.strip().str.upper()

        # Map common attack types to binary classification
        benign_labels = ['BENIGN', 'NORMAL', '0', 'LEGITIMATE']
        df_encoded['Binary_Label'] = labels.apply(lambda x: 0 if x in benign_labels else 1)

        # Keep original labels for multi-class classification
        df_encoded['Original_Label'] = df_encoded[self.target_column]
        df_encoded[self.target_column] = self.label_encoder.fit_transform(labels)

        # Print label distribution
        label_dist = df_encoded['Binary_Label'].value_counts()
        logger.info(f"Label distribution - Benign: {label_dist.get(0, 0)}, Malicious: {label_dist.get(1, 0)}")

        return df_encoded

    def normalize_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """Normalize numerical features"""
        logger.info("Normalizing features...")

        df_normalized = df.copy()

        if not self.feature_columns:
            logger.warning("No feature columns defined")
            return df_normalized

        # Select only existing feature columns
        existing_features = [col for col in self.feature_columns if col in df_normalized.columns]

        if fit:
            df_normalized[existing_features] = self.scaler.fit_transform(df_normalized[existing_features])
            self.is_fitted = True
        else:
            if not self.is_fitted:
                logger.error("Scaler not fitted. Call with fit=True first.")
                return df_normalized
            df_normalized[existing_features] = self.scaler.transform(df_normalized[existing_features])

        logger.info(f"Normalized {len(existing_features)} features")
        return df_normalized

    def prepare_training_data(self, df: pd.DataFrame, test_size: float = 0.2, random_state: int = 42) -> Tuple[
        np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Prepare data for training"""
        logger.info("Preparing training data...")

        if 'Binary_Label' not in df.columns:
            logger.error("Binary_Label column not found. Make sure to call encode_labels() first.")
            raise ValueError(
                "Binary_Label column is required for training. Call encode_labels() before prepare_training_data().")

        # Select features and target
        existing_features = [col for col in self.feature_columns if col in df.columns]

        if not existing_features:
            logger.error("No feature columns found for training")
            raise ValueError("No valid feature columns found. Make sure to call extract_features() first.")

        X = df[existing_features].values
        y = df['Binary_Label'].values

        if len(X) == 0 or len(y) == 0:
            raise ValueError("No data available for training after preprocessing")

        if len(np.unique(y)) < 2:
            logger.warning("Only one class found in target variable. This may cause training issues.")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        logger.info(f"Training data prepared - Train: {X_train.shape}, Test: {X_test.shape}")
        return X_train, X_test, y_train, y_test

    def process_pipeline(self, file_path: str, dataset_type: str = 'cicids') -> Tuple[
        np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Complete data processing pipeline for REAL network datasets"""
        logger.info("Starting REAL data processing pipeline...")

        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Dataset file not found: {file_path}")

            # Load data
            if dataset_type.lower() == 'cicids':
                df = self.load_cicids_dataset(file_path)
            elif dataset_type.lower() == 'zeek':
                df = self.load_zeek_logs([file_path])
            else:
                raise ValueError(f"Unsupported dataset type: {dataset_type}")

            if df.empty:
                raise ValueError("Dataset is empty - no real network data found")

            logger.info(f"Processing REAL network dataset with {len(df)} flows")

            # Process data
            df = self.clean_dataset(df)
            df = self.extract_features(df)
            df = self.encode_labels(df)
            df = self.normalize_features(df, fit=True)

            # Prepare training data
            X_train, X_test, y_train, y_test = self.prepare_training_data(df)

            logger.info("REAL data processing pipeline completed successfully!")
            return X_train, X_test, y_train, y_test

        except Exception as e:
            logger.error(f"Pipeline error: {str(e)}")
            raise

# Network Data Processor - REAL DATA ONLY
# This processor handles REAL network traffic datasets:
# 1. CICIDS2017/2018 datasets
# 2. NSL-KDD datasets
# 3. Zeek log files
# 4. CICFlowMeter CSV outputs
# No synthetic data generation - only processes REAL network traffic!
