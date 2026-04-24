print(" URL CHECKER MODULE LOADED")

import joblib
import pandas as pd
import os
import sys

# Allow importing from ml folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml")))

from feature_extraction import extract_features

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "ml",
    "phishing_model.pkl"
)

# Load model bundle ONCE at module import
try:
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    MODEL_FEATURES = bundle["features"]
    print(f" Model loaded successfully with {len(MODEL_FEATURES)} features")
    print(f"Model features: {MODEL_FEATURES}")
except Exception as e:
    print(f" Error loading model: {e}")
    raise

def check_url_ml(url):
    try:
        feature_dict = extract_features(url)
        print(f" Extracted features: {feature_dict}")

        df = pd.DataFrame([feature_dict])

        # Align columns exactly like training
        df = df.reindex(columns=MODEL_FEATURES, fill_value=0)

        # Debug: Show feature alignment
        print(f" Features after alignment: {list(df.columns)}")
        print(f" Feature values: {df.iloc[0].to_dict()}")

        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0][1]

        print(f" Prediction: {prediction} (1=phishing, 0=legitimate)")
        print(f" Confidence: {probability:.2%}")

        if prediction == 1:
            return "phishing", float(probability)
        else:
            return "legitimate", float(probability)  

    except Exception as e:
        print(f" Error in ML prediction: {e}")
        return "error", 0.0