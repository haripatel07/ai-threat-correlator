import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
import os

def train_model():
    """
    Loads the synthetic data, trains a classifier, and saves the model.
    """
    print("Starting model training...")
    data_path = 'data/training_data.csv'
    
    try:
        df = pd.read_csv(data_path)
    except FileNotFoundError:
        print(f"Error: Training data not found at {data_path}")
        print("Please run 'python src/model/generate_dataset.py' first.")
        return

    # Define our features (X) and target (y)
    target = 'severity'
    
    # These are the features the model will use to predict
    features = ['reputation_score', 'recency_days', 'threat_type', 'confidence']
    
    X = df[features]
    y = df[target]
    
    # A Pipeline is the best-practice way to do this.
    categorical_features = ['threat_type', 'confidence']
    numeric_features = ['reputation_score', 'recency_days']
    
    # Create a preprocessor to handle feature engineering
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', 'passthrough', numeric_features),
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
        ])

    # Create the full ML pipeline
    # 1. Preprocess the data
    # 2. Train a RandomForestClassifier
    model_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    
    # Split data for training and testing
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train the model!
    print("Training the Random Forest model...")
    model_pipeline.fit(X_train, y_train)
    
    # Check accuracy
    accuracy = model_pipeline.score(X_test, y_test)
    print(f"Model trained with accuracy: {accuracy * 100:.2f}%")
    
    # Save the trained model
    os.makedirs('models', exist_ok=True)
    model_path = 'models/threat_scorer.joblib'
    joblib.dump(model_pipeline, model_path)
    print(f"Model saved to {model_path}")
    
    joblib.dump(features, 'models/feature_columns.joblib')
    print("Feature columns saved.")

if __name__ == "__main__":
    train_model()