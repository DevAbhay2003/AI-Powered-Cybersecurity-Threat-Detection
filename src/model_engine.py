"""
AI Cybersecurity Threat Detection - Model Engine
Implements a Hybrid Detection Architecture:
1. Supervised Random Forest Classifier for known threat attribution
2. Unsupervised Isolation Forest for zero-day and anomalous traffic detection
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support
)

class HybridThreatDetector:
    def __init__(self, n_estimators=100, random_state=42):
        self.supervised_model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=16,
            min_samples_split=4,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1
        )
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.08,  # Expected proportion of anomalous outliers
            random_state=random_state,
            n_jobs=-1
        )
        self.is_trained = False

    def train(self, X_train, y_train, feature_names=None):
        """
        Trains both the supervised classifier and unsupervised anomaly detector.
        """
        print("[*] Training Supervised Random Forest Classifier...")
        self.supervised_model.fit(X_train, y_train)
        print("[+] Random Forest Classifier trained successfully.")

        # Train Isolation Forest (using benign subset if available, or full baseline)
        print("[*] Training Unsupervised Isolation Forest (Anomaly Detector)...")
        self.anomaly_detector.fit(X_train)
        print("[+] Isolation Forest trained successfully.")
        
        self.is_trained = True

    def evaluate(self, X_test, y_test, class_names):
        """
        Evaluates supervised model performance across all attack classes.
        """
        y_pred = self.supervised_model.predict(X_test)
        y_prob = self.supervised_model.predict_proba(X_test)
        
        acc = accuracy_score(y_test, y_pred)
        p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")
        
        report_dict = classification_report(
            y_test, y_pred, target_names=class_names, output_dict=True
        )
        report_text = classification_report(
            y_test, y_pred, target_names=class_names
        )
        cm = confusion_matrix(y_test, y_pred)
        
        # Anomaly detector metrics
        # -1 = anomaly, 1 = normal
        anomaly_scores = self.anomaly_detector.decision_function(X_test)
        
        metrics = {
            "accuracy": acc,
            "precision": p,
            "recall": r,
            "f1_score": f1,
            "classification_report": report_text,
            "confusion_matrix": cm,
            "anomaly_scores": anomaly_scores
        }
        
        return metrics

    def predict_hybrid(self, X_input, class_names):
        """
        Executes hybrid threat evaluation combining signature classification and anomaly detection.
        Returns:
            predicted_class: class name
            confidence: probability score
            anomaly_score: float score (more negative = more anomalous)
            is_anomaly: boolean
        """
        probs = self.supervised_model.predict_proba(X_input)
        pred_idx = np.argmax(probs, axis=1)
        confidences = np.max(probs, axis=1)
        predicted_classes = [class_names[idx] for idx in pred_idx]
        
        # Raw anomaly decision score (negative indicates outlier)
        raw_anomaly_scores = self.anomaly_detector.decision_function(X_input)
        is_anomaly = self.anomaly_detector.predict(X_input) == -1
        
        # Normalize anomaly score to 0 - 100 severity scale
        # Normal scores ~ +0.15, extreme anomalies ~ -0.30
        anomaly_severity = np.clip(
            (0.20 - raw_anomaly_scores) * 200, 0, 100
        ).round(1)
        
        results = []
        for i in range(len(predicted_classes)):
            p_class = predicted_classes[i]
            conf = float(confidences[i])
            anom_sev = float(anomaly_severity[i])
            is_anom = bool(is_anomaly[i])
            
            # Hybrid override: If classified as BENIGN but high anomaly score, flag as suspicious
            if p_class == "BENIGN" and anom_sev > 65.0:
                p_class = "SUSPICIOUS_ZERO_DAY_ANOMALY"
                conf = round(anom_sev / 100.0, 3)
                
            results.append({
                "predicted_threat": p_class,
                "confidence": conf,
                "anomaly_severity_score": anom_sev,
                "is_outlier": is_anom
            })
            
        return results

    def get_feature_importances(self, feature_names):
        """Returns dataframe of feature importance ranking."""
        importances = self.supervised_model.feature_importances_
        fi_df = pd.DataFrame({
            "feature": feature_names,
            "importance": importances
        }).sort_values(by="importance", ascending=False)
        return fi_df

    def save(self, model_dir="models/"):
        os.makedirs(model_dir, exist_ok=True)
        joblib.dump(self.supervised_model, os.path.join(model_dir, "threat_classifier.joblib"))
        joblib.dump(self.anomaly_detector, os.path.join(model_dir, "anomaly_detector.joblib"))
        print(f"[+] All models saved successfully under {model_dir}")

    @classmethod
    def load(cls, model_dir="models/"):
        detector = cls()
        sup_path = os.path.join(model_dir, "threat_classifier.joblib")
        anom_path = os.path.join(model_dir, "anomaly_detector.joblib")
        if not os.path.exists(sup_path) or not os.path.exists(anom_path):
            raise FileNotFoundError(f"Model files not found in {model_dir}.")
        detector.supervised_model = joblib.load(sup_path)
        detector.anomaly_detector = joblib.load(anom_path)
        detector.is_trained = True
        print(f"[+] Hybrid Threat Detector models loaded from {model_dir}")
        return detector
