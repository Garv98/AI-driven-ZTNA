# risk_score_utils.py

import joblib
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import MinMaxScaler

# Load pre-trained model
model = joblib.load("iso_forest.joblib")

# Reinitialize same preprocessing (match training phase)
imputer = SimpleImputer(strategy='mean')
scaler = MinMaxScaler(feature_range=(0, 100)) 

# Fit imputer and scaler on original data (once)
def initialize_reference_scaler(csv_file="login_data.csv"):
    import pandas as pd
    df = pd.read_csv(csv_file)
    X = df.iloc[:, 19:]

    X_imputed = imputer.fit_transform(X)
    raw_scores = -model.decision_function(X_imputed)
    scaler.fit(raw_scores.reshape(-1, 1))

# Call this once during app startup
initialize_reference_scaler()

# Score a new login attempt
def get_anomaly_score(input_dict):
    feature_order = [
        "Flow Duration", "Packet Size (mean)", "Flow Bytes per Second", "Flow Packets per Second",
        "Total Forward Packets", "Total Backward Packets", "IAT Forward", "IAT Backward",
        "Idle Duration", "Total Packets", "Total Bytes",
        "Packet Length Mean Forward", "Packet Length Mean Backward"
    ]
    
    values = [input_dict.get(feat, np.nan) for feat in feature_order]
    X = np.array(values).reshape(1, -1)

    X_imputed = imputer.transform(X)
    raw_score = -model.decision_function(X_imputed)[0]
    normalized_score = scaler.transform([[raw_score]])[0][0]
    is_anomaly = model.predict(X_imputed)[0]  # -1 = anomaly, 1 = normal

    return normalized_score, is_anomaly
