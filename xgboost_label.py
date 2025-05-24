# xgboost_predictor.py

import joblib
import pandas as pd

# Load the model once at import
xgb_model = joblib.load('xgboost_classifier.pkl')

# **MUST** exactly match your training columns!
REQUIRED_FEATURES = [
    "Flow Duration",
    "Packet Size (mean)",
    "Flow Bytes per Second",
    "Flow Packets per Second",
    "Active Duration",
    "IAT Forward",
    "IAT Backward",
    "Idle Duration",
    "Packet Length Mean Forward",
    "Packet Length Mean Backward",
    "Risk Score"
]

def predict_label(flow_features: dict) -> str:
    """
    Predict the label using the XGBoost model based on the given flow features.
    Assumes that flow_features already contains a valid 'Risk Score'.
    """
    try:
        # 1) Build the row in the exact order
        row = {feat: flow_features.get(feat, 0) for feat in REQUIRED_FEATURES}

        df = pd.DataFrame([row])
        # DEBUG: print out what you're actually passing to the model
        print(">> Predicting on DataFrame:", df.to_dict(orient="records")[0])

        # 2) Run the model
        label = xgb_model.predict(df)[0]

        return label

    except Exception as e:
        # Log the full traceback so you can see what went wrong
        import traceback
        traceback.print_exc()
        return "Prediction Failed"