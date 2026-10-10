"""
Cybersecurity Analytics Visualizer
Generates publication-quality charts for model evaluation, feature analysis,
anomaly distribution, and threat incident timelines.
"""

import os
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend suitable for scripts and servers
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd

sns.set_theme(style="darkgrid")
plt.rcParams.update({
    "font.family": "sans-serif",
    "figure.titlesize": 14,
    "axes.titlesize": 12,
    "axes.labelsize": 11
})

class SecurityVisualizer:
    def __init__(self, output_dir="images"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def plot_confusion_matrix(self, cm, class_names, filename="confusion_matrix.png"):
        """Plots normalized and annotated confusion matrix heatmap."""
        plt.figure(figsize=(9, 7))
        cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        
        sns.heatmap(
            cm_norm,
            annot=True,
            fmt=".2%",
            cmap="Blues",
            xticklabels=class_names,
            yticklabels=class_names,
            cbar=True,
            linewidths=0.5
        )
        plt.title("Cybersecurity Threat Detection - Normalized Confusion Matrix", pad=15, fontweight="bold")
        plt.xlabel("Predicted Class", labelpad=10)
        plt.ylabel("Ground Truth Class", labelpad=10)
        plt.xticks(rotation=30, ha="right")
        plt.yticks(rotation=0)
        plt.tight_layout()
        
        path = os.path.join(self.output_dir, filename)
        plt.savefig(path, dpi=300)
        plt.close()
        print(f"[+] Confusion matrix saved to: {path}")

    def plot_feature_importance(self, fi_df, top_n=10, filename="feature_importance.png"):
        """Plots top N most influential network features."""
        plt.figure(figsize=(10, 6))
        top_features = fi_df.head(top_n)
        
        palette = sns.color_palette("viridis", n_colors=top_n)
        sns.barplot(
            data=top_features,
            x="importance",
            y="feature",
            hue="feature",
            palette=palette,
            legend=False
        )
        
        plt.title(f"Top {top_n} Network Telemetry Features for Threat Classification", pad=15, fontweight="bold")
        plt.xlabel("Gini Feature Importance Score", labelpad=10)
        plt.ylabel("Network Telemetry Feature", labelpad=10)
        plt.tight_layout()
        
        path = os.path.join(self.output_dir, filename)
        plt.savefig(path, dpi=300)
        plt.close()
        print(f"[+] Feature importance plot saved to: {path}")

    def plot_anomaly_score_distribution(self, anomaly_scores, filename="anomaly_scores.png"):
        """Plots the anomaly score distribution from the Isolation Forest."""
        plt.figure(figsize=(9, 5))
        
        sns.histplot(
            anomaly_scores,
            kde=True,
            color="#e74c3c",
            bins=50,
            alpha=0.6
        )
        plt.axvline(x=0.0, color="#2c3e50", linestyle="--", linewidth=2, label="Anomaly Threshold (0.0)")
        plt.title("Isolation Forest Decision Score Distribution", pad=15, fontweight="bold")
        plt.xlabel("Decision Score (Negative values indicate malicious anomalies)", labelpad=10)
        plt.ylabel("Packet Flow Count", labelpad=10)
        plt.legend(loc="upper left")
        plt.tight_layout()
        
        path = os.path.join(self.output_dir, filename)
        plt.savefig(path, dpi=300)
        plt.close()
        print(f"[+] Anomaly score distribution saved to: {path}")

    def plot_threat_distribution(self, labels_series, filename="threat_distribution.png"):
        """Plots class balance donut chart."""
        plt.figure(figsize=(8, 8))
        counts = labels_series.value_counts()
        
        colors = sns.color_palette("tab10", n_colors=len(counts))
        plt.pie(
            counts.values,
            labels=counts.index,
            autopct="%1.1f%%",
            startangle=140,
            colors=colors,
            pctdistance=0.8,
            wedgeprops=dict(width=0.4, edgecolor='white', linewidth=2)
        )
        plt.title("Enterprise Telemetry Threat Category Distribution", pad=15, fontweight="bold")
        plt.tight_layout()
        
        path = os.path.join(self.output_dir, filename)
        plt.savefig(path, dpi=300)
        plt.close()
        print(f"[+] Threat distribution donut chart saved to: {path}")

    def plot_attack_timeline(self, alerts_history, filename="attack_timeline.png"):
        """Visualizes attack events intercepted during the real-time simulation."""
        if not alerts_history:
            return
            
        plt.figure(figsize=(12, 5))
        df_alerts = pd.DataFrame(alerts_history)
        df_alerts["event_idx"] = np.arange(len(df_alerts))
        
        color_map = {
            "CRITICAL": "#e74c3c",
            "HIGH": "#e67e22",
            "MEDIUM": "#f1c40f",
            "LOW": "#3498db"
        }
        point_colors = [color_map.get(s, "#95a5a6") for s in df_alerts["severity"]]
        
        plt.scatter(
            df_alerts["event_idx"],
            df_alerts["risk_score"],
            c=point_colors,
            s=80,
            alpha=0.85,
            edgecolors="black"
        )
        
        plt.plot(df_alerts["event_idx"], df_alerts["risk_score"], color="#7f8c8d", linestyle=":", alpha=0.5)
        
        plt.title("SOC Threat Incident Severity Timeline (Simulation Stream)", pad=15, fontweight="bold")
        plt.xlabel("Sequential Malicious Flow Event ID", labelpad=10)
        plt.ylabel("Risk Score (0 - 100)", labelpad=10)
        plt.ylim(0, 105)
        plt.tight_layout()
        
        path = os.path.join(self.output_dir, filename)
        plt.savefig(path, dpi=300)
        plt.close()
        print(f"[+] Attack timeline visualization saved to: {path}")
