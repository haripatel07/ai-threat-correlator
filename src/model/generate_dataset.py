import pandas as pd
import random

# Define the features our model will learn from
THREAT_TYPES = ['Malware', 'Botnet', 'Scanning', 'Phishing', 'Spam']
CONFIDENCE_LEVELS = ['High', 'Medium', 'Low']

def assign_severity(row):
    """
    This function acts as our "expert". It creates the logic
    that our AI will learn.
    """
    score = 0
    
    # Base score on reputation
    score += row['reputation_score']
    
    # Adjust score based on threat type
    if row['threat_type'] == 'Malware':
        score += 30
    elif row['threat_type'] == 'Botnet':
        score += 25
    elif row['threat_type'] == 'Phishing':
        score += 20
    elif row['threat_type'] == 'Scanning':
        score += 10
    
    # Adjust score based on confidence
    if row['confidence'] == 'High':
        score *= 1.5
    elif row['confidence'] == 'Medium':
        score *= 1.0
    else:
        score *= 0.5
        
    # Adjust score based on recency (newer = more dangerous)
    if row['recency_days'] < 7:
        score += 20
    elif row['recency_days'] < 30:
        score += 10
        
    # Assign final severity label
    if score > 150:
        return 'Critical'
    elif score > 100:
        return 'High'
    elif score > 60:
        return 'Medium'
    else:
        return 'Low'

def create_dataset(num_samples=5000):
    """
    Generates and saves a synthetic training dataset.
    """
    print(f"Generating {num_samples} synthetic threat samples...")
    data = []
    for _ in range(num_samples):
        data.append({
            'reputation_score': random.randint(20, 100),
            'recency_days': random.randint(0, 90),
            'threat_type': random.choice(THREAT_TYPES),
            'confidence': random.choice(CONFIDENCE_LEVELS)
        })
        
    df = pd.DataFrame(data)
    
    df['severity'] = df.apply(assign_severity, axis=1)
    
    # Save the dataset
    save_path = 'data/training_data.csv'
    df.to_csv(save_path, index=False)
    print(f"Synthetic training data saved to {save_path}")

if __name__ == "__main__":
    create_dataset()