import os
print("RUNNING FILE:", os.path.abspath(__file__))

import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

from feature_extraction import extract_features


# Load datasets
legit_df = pd.read_csv("dataset/legitimate.csv")
phish_df = pd.read_csv("dataset/phishing.csv")

#  Add labels
legit_df["label"] = 0   # Legitimate
phish_df["label"] = 1   # Phishing

#  Combine & shuffle
data = pd.concat([legit_df, phish_df], ignore_index=True)
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

# Feature extraction
feature_list = []
for url in data["url"]:
    feature_list.append(extract_features(url))

X = pd.DataFrame(feature_list)
y = data["label"]

print("Feature matrix shape:", X.shape)
print("Feature names:", list(X.columns))


#  Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


#  Train Random Forest
rf_model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

rf_model.fit(X_train, y_train)


#  Predictions
y_pred = rf_model.predict(X_test)


#  Confusion Matrix
cm = confusion_matrix(y_test, y_pred)

TN, FP, FN, TP = cm.ravel()

print("\n Confusion Matrix:")
print(cm)

print(f"\nTN (True Negative) : {TN}")
print(f"FP (False Positive): {FP}")
print(f"FN (False Negative): {FN}")
print(f"TP (True Positive) : {TP}")


#  Manual Evaluation Calculations

# Accuracy = (TP + TN) / (TP + TN + FP + FN)
accuracy = (TP + TN) / (TP + TN + FP + FN)

# Precision = TP / (TP + FP)
precision = TP / (TP + FP) if (TP + FP) != 0 else 0

# Recall = TP / (TP + FN)
recall = TP / (TP + FN) if (TP + FN) != 0 else 0

# F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) != 0 else 0


print("\n Random Forest Evaluation")
print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1-score : {f1:.4f}")


# SAVE MODEL + FEATURE NAMES
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

joblib.dump(
    {
        "model": rf_model,
        "features": list(X.columns)
    },
    MODEL_PATH
)

print(f"\n✅ Model and feature schema saved successfully at:\n{MODEL_PATH}")