"""
Network Traffic Preprocessing and Feature Engineering Module
Handles data cleansing, cybersecurity feature extraction, categorical encoding,
and robust scaling for downstream ML detectors.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

class NetworkTrafficPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.target_encoder = LabelEncoder()
        self.feature_columns = []
        self.categorical_cols = ["protocol", "service", "flag"]
        self.numerical_cols = [
            "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
            "failed_logins", "dst_port", "byte_rate", "packet_rate",
            "bytes_per_packet", "packet_ratio", "byte_ratio",
            "is_privileged_port"
        ]

    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extracts high-signal cybersecurity domain features from raw flow telemetry.
        """
        df = df.copy()
        
        # Calculate Rates with epsilon to prevent division by zero
        eps = 1e-5
        duration_safe = df["duration"] + eps
        
        df["byte_rate"] = (df["src_bytes"] + df["dst_bytes"]) / duration_safe
        df["packet_rate"] = (df["src_pkts"] + df["dst_pkts"]) / duration_safe
        df["bytes_per_packet"] = (df["src_bytes"] + df["dst_bytes"]) / (df["src_pkts"] + df["dst_pkts"] + eps)
        df["packet_ratio"] = df["src_pkts"] / (df["dst_pkts"] + 1.0)
        df["byte_ratio"] = df["src_bytes"] / (df["dst_bytes"] + 1.0)
        
        # Port security classification
        df["is_privileged_port"] = (df["dst_port"] < 1024).astype(int)
        
        # Log-transform extreme skewed variables for stability
        df["log_src_bytes"] = np.log1p(df["src_bytes"])
        df["log_dst_bytes"] = np.log1p(df["dst_bytes"])
        df["log_byte_rate"] = np.log1p(np.maximum(0, df["byte_rate"]))
        
        return df

    def fit_transform(self, df: pd.DataFrame, target_col: str = "label"):
        """
        Fits encoders/scalers on training data and returns processed features and target.
        """
        df_feats = self.engineer_features(df)
        
        # Encode Categorical features
        for col in self.categorical_cols:
            le = LabelEncoder()
            df_feats[col] = le.fit_transform(df_feats[col].astype(str))
            self.label_encoders[col] = le
            
        all_numeric = self.numerical_cols + ["log_src_bytes", "log_dst_bytes", "log_byte_rate"]
        self.feature_columns = self.categorical_cols + all_numeric
        
        X = df_feats[self.feature_columns].copy()
        X_scaled = self.scaler.fit_transform(X)
        X_df = pd.DataFrame(X_scaled, columns=self.feature_columns)
        
        y = None
        if target_col in df:
            y = self.target_encoder.fit_transform(df[target_col])
            
        return X_df, y

    def transform(self, df: pd.DataFrame):
        """
        Transforms unseen test or real-time simulation stream packets.
        """
        df_feats = self.engineer_features(df)
        
        for col in self.categorical_cols:
            le = self.label_encoders[col]
            # Handle unseen categories gracefully by mapping to closest known class
            known_classes = set(le.classes_)
            df_feats[col] = df_feats[col].apply(lambda s: s if s in known_classes else le.classes_[0])
            df_feats[col] = le.transform(df_feats[col].astype(str))
            
        X = df_feats[self.feature_columns].copy()
        X_scaled = self.scaler.transform(X)
        return pd.DataFrame(X_scaled, columns=self.feature_columns)

    def inverse_transform_labels(self, y_encoded):
        return self.target_encoder.inverse_transform(y_encoded)

    def save(self, filepath: str = "models/preprocessor.joblib"):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        print(f"[+] Preprocessor saved to {filepath}")

    @staticmethod
    def load(filepath: str = "models/preprocessor.joblib"):
        preprocessor = joblib.load(filepath)
        print(f"[+] Preprocessor loaded from {filepath}")
        return preprocessor

def prepare_train_test_data(data_path="data/raw_network_traffic.csv", test_size=0.2, random_state=42):
    """
    Loads raw dataset, executes preprocessing pipeline, and performs stratified split.
    """
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Run data_generator.py first.")
        
    df = pd.read_csv(data_path)
    preprocessor = NetworkTrafficPreprocessor()
    
    X, y = preprocessor.fit_transform(df, target_col="label")
    preprocessor.save("models/preprocessor.joblib")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    print(f"[*] Training samples: {X_train.shape[0]} | Testing samples: {X_test.shape[0]}")
    return X_train, X_test, y_train, y_test, preprocessor
