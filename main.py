import os
import joblib
import pandas as pd
import random
import ipaddress
from src.collector.feed_downloader import download_feed
from src.collector.log_parser import load_threat_feed, parse_server_log

# --- CONFIGURATION ---
MODEL_PATH = "models/threat_scorer.joblib"
COLUMNS_PATH = "models/feature_columns.joblib"

# --- 1. LOAD THE TRAINED AI MODEL ---
try:
    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(COLUMNS_PATH)
    print("AI threat scoring model loaded successfully.")
except FileNotFoundError:
    print(f"Error: Model file not found at {MODEL_PATH}")
    print("Please run the training scripts in 'src/model/' first.")
    exit()
except Exception as e:
    print(f"Error loading model: {e}")
    exit()


def get_threat_context(ip_address):
    """
    *** MOCK FUNCTION ***
    In a real-world app, this function would query external APIs 
    (like AbuseIPDB, VirusTotal, etc.) to get context for a malicious IP.
    
    For this project, we will generate realistic, random data.
    """
    print(f"  > Simulating intelligence gathering for: {ip_address}")
    
    # We make 'Malware' and 'Botnet' more likely for our known bad IP
    if ip_address == "1.186.20.106":
        threat_type = random.choice(['Malware', 'Botnet', 'Malware'])
        confidence = 'High'
    else:
        threat_type = random.choice(['Scanning', 'Phishing', 'Spam'])
        confidence = random.choice(['Medium', 'Low'])

    return {
        'reputation_score': random.randint(60, 100), # Known bad IPs have high scores
        'recency_days': random.randint(1, 30),       # Recently seen
        'threat_type': threat_type,
        'confidence': confidence
    }

def score_threats(matches):
    """
    Uses the loaded AI model to score a list of malicious IPs.
    """
    print("-" * 40)
    print("Scoring threats with AI model...")
    
    threat_data = []
    for ip in matches:
        context = get_threat_context(ip)
        context['ip'] = ip  # Add the IP for reference
        threat_data.append(context)

    if not threat_data:
        print("No threats to score.")
        return

    # Convert the list of threat data into a DataFrame
    df = pd.DataFrame(threat_data)
    
    X_predict = df[feature_columns]
    
    # --- AI PREDICTION ---
    severities = model.predict(X_predict)
    
    # Get the predicted probabilities 
    probabilities = model.predict_proba(X_predict)
    classes = model.classes_
    
    # Add results 
    df['severity'] = severities
    # Add a numeric "priority" score for sorting
    df['priority_score'] = [prob[list(classes).index('Critical')] * 100 + \
                            prob[list(classes).index('High')] * 50 \
                            for prob in probabilities]
    
    # Sort by priority
    df_sorted = df.sort_values(by='priority_score', ascending=False)
    
    print("\n--- [!!!] PRIORITIZED THREAT ALERTS [!!!] ---")
    for _, row in df_sorted.iterrows():
        print(f"\n  [ SEVERITY: {row['severity'].upper()} ]")
        print(f"  IP Address:    {row['ip']}")
        print(f"  Threat Type:   {row['threat_type']}")
        print(f"  Reputation:    {row['reputation_score']}")
        print(f"  Recency (Days): {row['recency_days']}")
        print(f"  Confidence:    {row['confidence']}")
    
    
def run_correlation():
    """
    Main function to run the threat intelligence correlation.
    """
    print("--- Starting Threat Intelligence Correlation ---")
    
    if not download_feed():
        print("Halting execution due to feed download failure.")
        return
        
    print("-" * 40)
    
    malicious_ips = load_threat_feed()
    if malicious_ips is None:
        return
        
    print("-" * 40)

    visitor_ips = parse_server_log()
    if visitor_ips is None:
        return

    print("-" * 40)
    
    print("Correlating visitor IPs against threat feed...")
    matches = set()
    for visitor_ip in visitor_ips:
        visitor_ip_obj = ipaddress.ip_address(visitor_ip)
        for cidr_block in malicious_ips:
            try:
                network = ipaddress.ip_network(cidr_block, strict=False)
                if visitor_ip_obj in network:
                    matches.add(visitor_ip)
                    break
            except ValueError:
                # Skip invalid CIDR blocks
                continue
    
    if matches:
        print(f"\n[!] Found {len(matches)} match(es) in logs.")
        # --- STAGE 5: Score the matches ---
        score_threats(matches)
    else:
        print("\n[+] No malicious IPs found in server logs. System clean.")

    print("\n--- Correlation Complete ---")

if __name__ == "__main__":
    if not os.path.exists(MODEL_PATH) or not os.path.exists(COLUMNS_PATH):
        print("Model not found! Running training scripts first...")
        
        from src.model.generate_dataset import create_dataset
        from src.model.train_model import train_model
        
        create_dataset()
        train_model()
        
        # Reload the model
        try:
            model = joblib.load(MODEL_PATH)
            feature_columns = joblib.load(COLUMNS_PATH)
            print("AI threat scoring model loaded successfully.")
        except Exception as e:
            print(f"Failed to load model after training: {e}")
            exit()
    
    # Run the main application
    run_correlation()