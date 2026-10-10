"""
AI-Powered Cybersecurity Threat Detection System
Main Execution Controller and CLI Pipeline Orchestrator
"""

import os
import sys
import argparse
import pandas as pd
from src.data_generator import generate_network_traffic_dataset, generate_stream_simulation_batch
from src.preprocessor import NetworkTrafficPreprocessor, prepare_train_test_data
from src.model_engine import HybridThreatDetector
from src.visualizer import SecurityVisualizer
from src.simulate_stream import run_simulation
from src.alert_engine import BOLD, GREEN, CYAN, RED, YELLOW, RESET

def run_train_and_evaluate(data_path="data/raw_network_traffic.csv"):
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}             STEP 1: DATASET GENERATION & PREPARATION                   {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")
    
    if not os.path.exists(data_path):
        generate_network_traffic_dataset(num_records=12000, output_path=data_path)
    else:
        print(f"[+] Found existing dataset at {data_path}.")
        
    df_raw = pd.read_csv(data_path)
    
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}             STEP 2: FEATURE ENGINEERING & SCALING                      {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")
    
    X_train, X_test, y_train, y_test, preprocessor = prepare_train_test_data(
        data_path=data_path, test_size=0.2, random_state=42
    )
    class_names = list(preprocessor.target_encoder.classes_)
    feature_names = preprocessor.feature_columns
    
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}             STEP 3: HYBRID MODEL TRAINING (RF + ISOLATION FOREST)      {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")
    
    detector = HybridThreatDetector(n_estimators=100, random_state=42)
    detector.train(X_train, y_train)
    detector.save(model_dir="models/")
    
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}             STEP 4: MODEL EVALUATION & PERFORMANCE METRICS             {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")
    
    metrics = detector.evaluate(X_test, y_test, class_names)
    
    print(f" {BOLD}Accuracy Score :{RESET} {metrics['accuracy'] * 100:.2f}%")
    print(f" {BOLD}Precision Score:{RESET} {metrics['precision'] * 100:.2f}%")
    print(f" {BOLD}Recall Score   :{RESET} {metrics['recall'] * 100:.2f}%")
    print(f" {BOLD}F1 Score       :{RESET} {metrics['f1_score'] * 100:.2f}%\n")
    print(f"Classification Report:\n{metrics['classification_report']}")
    
    # Save classification report
    os.makedirs("outputs", exist_ok=True)
    with open("outputs/classification_report.txt", "w") as f:
        f.write(f"Accuracy: {metrics['accuracy']:.4f}\n")
        f.write(f"Precision: {metrics['precision']:.4f}\n")
        f.write(f"Recall: {metrics['recall']:.4f}\n")
        f.write(f"F1-Score: {metrics['f1_score']:.4f}\n\n")
        f.write(metrics["classification_report"])
    print("[+] Evaluation report saved to outputs/classification_report.txt")
    
    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}             STEP 5: GENERATING CHARTS & VISUAL ASSETS                 {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")
    
    visualizer = SecurityVisualizer(output_dir="images")
    visualizer.plot_confusion_matrix(metrics["confusion_matrix"], class_names)
    
    fi_df = detector.get_feature_importances(feature_names)
    visualizer.plot_feature_importance(fi_df, top_n=10)
    visualizer.plot_anomaly_score_distribution(metrics["anomaly_scores"])
    visualizer.plot_threat_distribution(df_raw["label"])
    
    print(f"\n{BOLD}{GREEN}[+] Training, Evaluation, and Visualizations Completed Successfully!{RESET}\n")

def main():
    parser = argparse.ArgumentParser(description="AI-Powered Cybersecurity Threat Detection System")
    parser.add_argument("--train", action="store_true", help="Generate data and train threat detection models")
    parser.add_argument("--simulate", action="store_true", help="Run real-time virtual cyber attack stream simulation")
    parser.add_argument("--all", action="store_true", help="Run full end-to-end pipeline (Train + Evaluate + Simulate)")
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1 or args.all:
        print(f"\n{BOLD}{YELLOW}>>> Running Complete End-to-End Cybersecurity AI Pipeline <<<{RESET}")
        run_train_and_evaluate()
        run_simulation(delay_seconds=0.01)
    elif args.train:
        run_train_and_evaluate()
    elif args.simulate:
        run_simulation(delay_seconds=0.02)

if __name__ == "__main__":
    main()
