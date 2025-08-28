import pandas as pd
import numpy as np
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import logging
from typing import List, Dict, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkFeatureEngineer:
    """
    Advanced feature engineering for network intrusion detection.
    Includes statistical features, flow-based features, and feature selection.
    """
    
    def __init__(self):
        self.feature_selector = None
        self.pca = None
        self.scaler = StandardScaler()
        self.selected_features = []
        self.engineered_features = []
        
    def extract_statistical_features(self, df: pd.DataFrame, flow_columns: List[str]) -> pd.DataFrame:
        """Extract statistical features from network flow data"""
        logger.info("Extracting statistical features...")
        
        df_stats = df.copy()
        
        try:
            # Basic statistical features for each flow column
            for col in flow_columns:
                if col in df_stats.columns and df_stats[col].dtype in ['int64', 'float64']:
                    # Remove infinite values
                    df_stats[col] = df_stats[col].replace([np.inf, -np.inf], np.nan)
                    df_stats[col] = df_stats[col].fillna(df_stats[col].median())
                    
                    # Statistical measures
                    col_data = df_stats[col]
                    
                    # Variance and standard deviation
                    df_stats[f'{col}_variance'] = col_data.rolling(window=5, min_periods=1).var()
                    df_stats[f'{col}_std'] = col_data.rolling(window=5, min_periods=1).std()
                    
                    # Skewness and kurtosis (if scipy available)
                    try:
                        from scipy import stats
                        df_stats[f'{col}_skewness'] = col_data.rolling(window=10, min_periods=1).skew()
                        df_stats[f'{col}_kurtosis'] = col_data.rolling(window=10, min_periods=1).kurt()
                    except ImportError:
                        logger.warning("Scipy not available, skipping skewness and kurtosis")
                    
                    # Percentiles
                    df_stats[f'{col}_q25'] = col_data.rolling(window=10, min_periods=1).quantile(0.25)
                    df_stats[f'{col}_q75'] = col_data.rolling(window=10, min_periods=1).quantile(0.75)
                    df_stats[f'{col}_iqr'] = df_stats[f'{col}_q75'] - df_stats[f'{col}_q25']
                    
        except Exception as e:
            logger.warning(f"Error in statistical feature extraction: {str(e)}")
        
        # Fill any remaining NaN values
        df_stats = df_stats.fillna(0)
        
        logger.info(f"Statistical features extracted. New shape: {df_stats.shape}")
        return df_stats
    
    def extract_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract network flow-specific features"""
        logger.info("Extracting flow-based features...")
        
        df_flow = df.copy()
        
        try:
            # Packet-based features
            if 'Total Fwd Packets' in df_flow.columns and 'Total Backward Packets' in df_flow.columns:
                df_flow['Total_Packets'] = df_flow['Total Fwd Packets'] + df_flow['Total Backward Packets']
                df_flow['Fwd_Bwd_Packet_Ratio'] = df_flow['Total Fwd Packets'] / (df_flow['Total Backward Packets'] + 1)
                df_flow['Packet_Asymmetry'] = abs(df_flow['Total Fwd Packets'] - df_flow['Total Backward Packets'])
            
            # Byte-based features
            if 'Total Length of Fwd Packets' in df_flow.columns and 'Total Length of Bwd Packets' in df_flow.columns:
                df_flow['Total_Bytes'] = df_flow['Total Length of Fwd Packets'] + df_flow['Total Length of Bwd Packets']
                df_flow['Fwd_Bwd_Bytes_Ratio'] = df_flow['Total Length of Fwd Packets'] / (df_flow['Total Length of Bwd Packets'] + 1)
                df_flow['Bytes_Asymmetry'] = abs(df_flow['Total Length of Fwd Packets'] - df_flow['Total Length of Bwd Packets'])
                
                # Average packet sizes
                df_flow['Avg_Fwd_Packet_Size'] = df_flow['Total Length of Fwd Packets'] / (df_flow['Total Fwd Packets'] + 1)
                df_flow['Avg_Bwd_Packet_Size'] = df_flow['Total Length of Bwd Packets'] / (df_flow['Total Backward Packets'] + 1)
                df_flow['Avg_Packet_Size'] = df_flow['Total_Bytes'] / (df_flow['Total_Packets'] + 1)
            
            # Time-based features
            if 'Flow Duration' in df_flow.columns:
                df_flow['Flow_Duration_Log'] = np.log1p(df_flow['Flow Duration'])
                
                if 'Total_Packets' in df_flow.columns:
                    df_flow['Packets_Per_Second'] = df_flow['Total_Packets'] / (df_flow['Flow Duration'] / 1000000 + 1)  # Convert to seconds
                
                if 'Total_Bytes' in df_flow.columns:
                    df_flow['Bytes_Per_Second'] = df_flow['Total_Bytes'] / (df_flow['Flow Duration'] / 1000000 + 1)
            
            # Inter-arrival time features
            if 'Flow IAT Mean' in df_flow.columns:
                df_flow['Flow_IAT_Log'] = np.log1p(df_flow['Flow IAT Mean'])
                
                if 'Flow IAT Std' in df_flow.columns:
                    df_flow['Flow_IAT_CV'] = df_flow['Flow IAT Std'] / (df_flow['Flow IAT Mean'] + 1)  # Coefficient of variation
            
            # Flag-based features
            flag_columns = [col for col in df_flow.columns if 'Flag' in col or 'flag' in col]
            if flag_columns:
                df_flow['Total_Flags'] = df_flow[flag_columns].sum(axis=1)
                df_flow['Flag_Diversity'] = (df_flow[flag_columns] > 0).sum(axis=1)
            
            # Protocol-based features (if protocol information available)
            if 'Protocol' in df_flow.columns:
                # One-hot encode protocols
                protocol_dummies = pd.get_dummies(df_flow['Protocol'], prefix='Protocol')
                df_flow = pd.concat([df_flow, protocol_dummies], axis=1)
            
            # Port-based features
            port_columns = [col for col in df_flow.columns if 'Port' in col and df_flow[col].dtype in ['int64', 'float64']]
            for col in port_columns:
                # Well-known ports (0-1023)
                df_flow[f'{col}_is_wellknown'] = (df_flow[col] <= 1023).astype(int)
                # Registered ports (1024-49151)
                df_flow[f'{col}_is_registered'] = ((df_flow[col] > 1023) & (df_flow[col] <= 49151)).astype(int)
                # Dynamic ports (49152-65535)
                df_flow[f'{col}_is_dynamic'] = (df_flow[col] > 49151).astype(int)
            
        except Exception as e:
            logger.warning(f"Error in flow feature extraction: {str(e)}")
        
        # Replace infinite values and fill NaN
        df_flow = df_flow.replace([np.inf, -np.inf], np.nan)
        df_flow = df_flow.fillna(0)
        
        logger.info(f"Flow features extracted. New shape: {df_flow.shape}")
        return df_flow
    
    def extract_temporal_features(self, df: pd.DataFrame, timestamp_col: str = None) -> pd.DataFrame:
        """Extract temporal features from network traffic"""
        logger.info("Extracting temporal features...")
        
        df_temporal = df.copy()
        
        try:
            # If timestamp column is provided
            if timestamp_col and timestamp_col in df_temporal.columns:
                df_temporal[timestamp_col] = pd.to_datetime(df_temporal[timestamp_col])
                
                # Extract time components
                df_temporal['Hour'] = df_temporal[timestamp_col].dt.hour
                df_temporal['Day_of_Week'] = df_temporal[timestamp_col].dt.dayofweek
                df_temporal['Month'] = df_temporal[timestamp_col].dt.month
                
                # Time-based patterns
                df_temporal['Is_Weekend'] = (df_temporal['Day_of_Week'] >= 5).astype(int)
                df_temporal['Is_Business_Hours'] = ((df_temporal['Hour'] >= 9) & (df_temporal['Hour'] <= 17)).astype(int)
                df_temporal['Is_Night'] = ((df_temporal['Hour'] >= 22) | (df_temporal['Hour'] <= 6)).astype(int)
                
                # Cyclical encoding for time features
                df_temporal['Hour_sin'] = np.sin(2 * np.pi * df_temporal['Hour'] / 24)
                df_temporal['Hour_cos'] = np.cos(2 * np.pi * df_temporal['Hour'] / 24)
                df_temporal['Day_sin'] = np.sin(2 * np.pi * df_temporal['Day_of_Week'] / 7)
                df_temporal['Day_cos'] = np.cos(2 * np.pi * df_temporal['Day_of_Week'] / 7)
            
            # Flow sequence features (if data is sequential)
            if len(df_temporal) > 1:
                # Rolling window features
                window_sizes = [5, 10, 20]
                numeric_cols = df_temporal.select_dtypes(include=[np.number]).columns
                
                for window in window_sizes:
                    for col in numeric_cols[:5]:  # Limit to first 5 numeric columns to avoid too many features
                        if col in df_temporal.columns:
                            df_temporal[f'{col}_rolling_mean_{window}'] = df_temporal[col].rolling(window=window, min_periods=1).mean()
                            df_temporal[f'{col}_rolling_std_{window}'] = df_temporal[col].rolling(window=window, min_periods=1).std()
                
        except Exception as e:
            logger.warning(f"Error in temporal feature extraction: {str(e)}")
        
        # Fill NaN values
        df_temporal = df_temporal.fillna(0)
        
        logger.info(f"Temporal features extracted. New shape: {df_temporal.shape}")
        return df_temporal
    
    def select_features_univariate(self, X: np.ndarray, y: np.ndarray, k: int = 50) -> Tuple[np.ndarray, List[int]]:
        """Select top k features using univariate statistical tests"""
        logger.info(f"Selecting top {k} features using univariate selection...")
        
        # Use f_classif for classification
        selector = SelectKBest(score_func=f_classif, k=k)
        X_selected = selector.fit_transform(X, y)
        
        selected_indices = selector.get_support(indices=True)
        scores = selector.scores_
        
        self.feature_selector = selector
        self.selected_features = selected_indices.tolist()
        
        logger.info(f"Selected {X_selected.shape[1]} features out of {X.shape[1]}")
        return X_selected, selected_indices.tolist()
    
    def select_features_mutual_info(self, X: np.ndarray, y: np.ndarray, k: int = 50) -> Tuple[np.ndarray, List[int]]:
        """Select features using mutual information"""
        logger.info(f"Selecting top {k} features using mutual information...")
        
        selector = SelectKBest(score_func=mutual_info_classif, k=k)
        X_selected = selector.fit_transform(X, y)
        
        selected_indices = selector.get_support(indices=True)
        
        self.feature_selector = selector
        self.selected_features = selected_indices.tolist()
        
        logger.info(f"Selected {X_selected.shape[1]} features out of {X.shape[1]}")
        return X_selected, selected_indices.tolist()
    
    def select_features_importance(self, X: np.ndarray, y: np.ndarray, k: int = 50) -> Tuple[np.ndarray, List[int]]:
        """Select features using Random Forest feature importance"""
        logger.info(f"Selecting top {k} features using Random Forest importance...")
        
        # Train Random Forest
        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf.fit(X, y)
        
        # Get feature importances
        importances = rf.feature_importances_
        indices = np.argsort(importances)[::-1][:k]
        
        X_selected = X[:, indices]
        
        self.selected_features = indices.tolist()
        
        logger.info(f"Selected {X_selected.shape[1]} features out of {X.shape[1]}")
        return X_selected, indices.tolist()
    
    def apply_pca(self, X: np.ndarray, n_components: float = 0.95) -> np.ndarray:
        """Apply PCA for dimensionality reduction"""
        logger.info(f"Applying PCA with {n_components} variance retention...")
        
        self.pca = PCA(n_components=n_components, random_state=42)
        X_pca = self.pca.fit_transform(X)
        
        explained_variance = self.pca.explained_variance_ratio_.sum()
        logger.info(f"PCA reduced dimensions from {X.shape[1]} to {X_pca.shape[1]}")
        logger.info(f"Explained variance: {explained_variance:.4f}")
        
        return X_pca
    
    def create_interaction_features(self, df: pd.DataFrame, feature_pairs: List[Tuple[str, str]] = None) -> pd.DataFrame:
        """Create interaction features between important features"""
        logger.info("Creating interaction features...")
        
        df_interactions = df.copy()
        
        try:
            if feature_pairs is None:
                # Auto-select important numeric features for interactions
                numeric_cols = df_interactions.select_dtypes(include=[np.number]).columns.tolist()
                # Remove target columns
                target_cols = ['Label', 'Binary_Label', 'Original_Label']
                numeric_cols = [col for col in numeric_cols if col not in target_cols]
                
                # Select top features based on variance (simple heuristic)
                if len(numeric_cols) > 10:
                    variances = df_interactions[numeric_cols].var()
                    top_features = variances.nlargest(10).index.tolist()
                else:
                    top_features = numeric_cols
                
                # Create pairs from top features
                feature_pairs = []
                for i in range(len(top_features)):
                    for j in range(i+1, min(i+4, len(top_features))):  # Limit interactions
                        feature_pairs.append((top_features[i], top_features[j]))
            
            # Create interaction features
            for feat1, feat2 in feature_pairs[:20]:  # Limit to 20 interactions
                if feat1 in df_interactions.columns and feat2 in df_interactions.columns:
                    # Multiplication
                    df_interactions[f'{feat1}_x_{feat2}'] = df_interactions[feat1] * df_interactions[feat2]
                    
                    # Ratio (avoid division by zero)
                    df_interactions[f'{feat1}_div_{feat2}'] = df_interactions[feat1] / (df_interactions[feat2] + 1e-8)
                    
                    # Difference
                    df_interactions[f'{feat1}_diff_{feat2}'] = df_interactions[feat1] - df_interactions[feat2]
        
        except Exception as e:
            logger.warning(f"Error creating interaction features: {str(e)}")
        
        # Replace infinite values
        df_interactions = df_interactions.replace([np.inf, -np.inf], np.nan)
        df_interactions = df_interactions.fillna(0)
        
        logger.info(f"Interaction features created. New shape: {df_interactions.shape}")
        return df_interactions
    
    def engineer_all_features(self, df: pd.DataFrame, target_col: str = 'Label') -> pd.DataFrame:
        """Apply all feature engineering techniques"""
        logger.info("Starting comprehensive feature engineering...")
        
        # Identify numeric columns for processing
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        if target_col in numeric_cols:
            numeric_cols.remove(target_col)
        
        # Apply feature engineering steps
        df_engineered = df.copy()
        
        # 1. Statistical features
        df_engineered = self.extract_statistical_features(df_engineered, numeric_cols[:10])  # Limit to avoid too many features
        
        # 2. Flow-based features
        df_engineered = self.extract_flow_features(df_engineered)
        
        # 3. Temporal features (if applicable)
        df_engineered = self.extract_temporal_features(df_engineered)
        
        # 4. Interaction features
        df_engineered = self.create_interaction_features(df_engineered)
        
        # Store engineered feature names
        original_features = set(df.columns)
        new_features = set(df_engineered.columns) - original_features
        self.engineered_features = list(new_features)
        
        logger.info(f"Feature engineering completed. Original: {df.shape[1]}, Engineered: {df_engineered.shape[1]}")
        logger.info(f"Added {len(self.engineered_features)} new features")
        
        return df_engineered
    
    def get_feature_importance_report(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> Dict:
        """Generate feature importance report"""
        logger.info("Generating feature importance report...")
        
        # Random Forest importance
        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf.fit(X, y)
        rf_importance = rf.feature_importances_
        
        # Univariate scores
        selector = SelectKBest(score_func=f_classif, k='all')
        selector.fit(X, y)
        univariate_scores = selector.scores_
        
        # Create report
        report = {
            'feature_names': feature_names,
            'rf_importance': rf_importance.tolist(),
            'univariate_scores': univariate_scores.tolist(),
            'top_rf_features': [feature_names[i] for i in np.argsort(rf_importance)[::-1][:20]],
            'top_univariate_features': [feature_names[i] for i in np.argsort(univariate_scores)[::-1][:20]]
        }
        
        return report

# Example usage and testing
if __name__ == "__main__":
    logger.info("Testing Network Feature Engineering...")
    
    # Create sample network traffic data
    np.random.seed(42)
    n_samples = 1000
    
    sample_data = {
        'Flow Duration': np.random.exponential(1000, n_samples),
        'Total Fwd Packets': np.random.poisson(10, n_samples),
        'Total Backward Packets': np.random.poisson(8, n_samples),
        'Total Length of Fwd Packets': np.random.normal(1500, 500, n_samples),
        'Total Length of Bwd Packets': np.random.normal(1200, 400, n_samples),
        'Flow IAT Mean': np.random.exponential(100, n_samples),
        'Flow IAT Std': np.random.exponential(50, n_samples),
        'Fwd PSH Flags': np.random.binomial(1, 0.1, n_samples),
        'Bwd PSH Flags': np.random.binomial(1, 0.1, n_samples),
        'Fwd URG Flags': np.random.binomial(1, 0.05, n_samples),
        'Protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
        'Destination Port': np.random.choice([80, 443, 22, 21, 25, 53] + list(range(1024, 65536)), n_samples),
    }
    
    # Add labels
    labels = ['BENIGN'] * 800 + ['DDoS'] * 100 + ['PortScan'] * 50 + ['BruteForce'] * 50
    np.random.shuffle(labels)
    sample_data['Label'] = labels
    
    # Create DataFrame
    df_sample = pd.DataFrame(sample_data)
    
    # Initialize feature engineer
    feature_engineer = NetworkFeatureEngineer()
    
    try:
        # Test feature engineering
        print(f"Original dataset shape: {df_sample.shape}")
        
        # Apply all feature engineering
        df_engineered = feature_engineer.engineer_all_features(df_sample, target_col='Label')
        print(f"Engineered dataset shape: {df_engineered.shape}")
        print(f"Added features: {len(feature_engineer.engineered_features)}")
        
        # Prepare data for feature selection
        target_mapping = {'BENIGN': 0, 'DDoS': 1, 'PortScan': 1, 'BruteForce': 1}
        y = df_engineered['Label'].map(target_mapping).values
        
        # Get numeric features only
        numeric_features = df_engineered.select_dtypes(include=[np.number]).columns.tolist()
        numeric_features = [col for col in numeric_features if col != 'Label']
        X = df_engineered[numeric_features].values
        
        print(f"Features for selection: {len(numeric_features)}")
        
        # Test feature selection methods
        print("\n=== Feature Selection Results ===")
        
        # Univariate selection
        X_uni, selected_uni = feature_engineer.select_features_univariate(X, y, k=20)
        print(f"Univariate selection: {X_uni.shape[1]} features")
        
        # Mutual information
        X_mi, selected_mi = feature_engineer.select_features_mutual_info(X, y, k=20)
        print(f"Mutual information: {X_mi.shape[1]} features")
        
        # Random Forest importance
        X_rf, selected_rf = feature_engineer.select_features_importance(X, y, k=20)
        print(f"Random Forest importance: {X_rf.shape[1]} features")
        
        # PCA
        X_pca = feature_engineer.apply_pca(X, n_components=0.95)
        print(f"PCA: {X_pca.shape[1]} components")
        
        # Feature importance report
        report = feature_engineer.get_feature_importance_report(X, y, numeric_features)
        print(f"\nTop 5 RF features: {report['top_rf_features'][:5]}")
        print(f"Top 5 Univariate features: {report['top_univariate_features'][:5]}")
        
        print("\nFeature engineering testing completed successfully!")
        
    except Exception as e:
        print(f"Error in feature engineering: {str(e)}")
