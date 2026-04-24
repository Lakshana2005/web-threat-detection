import sys
import os

# Allow importing from ml folder
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml"))
)

from explainability.url_explainer import explain_url
from utils.risk_mapper import map_risk
from feature_extraction import extract_features
from url_checker import check_url_ml
from vt_client import scan_url_virustotal
from urllib.parse import urlparse

#  IMPORT THE VALIDATOR
from utils.url_validator import normalize_and_validate, is_valid_url

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def final_url_verdict(url):
    # VALIDATE URL FIRST
    normalized_url, is_valid, error_message = normalize_and_validate(url)
    
    if not is_valid:
        # Return error response for invalid URL
        return {
            "url": url,
            "error": True,
            "error_message": error_message,
            "ml_result": "error",
            "ml_confidence": 0.0,
            "risk_level": "INVALID",
            "explanation": [f"{error_message}"],
            "virustotal": {},
            "final_status": "invalid"
        }
    
    url = normalized_url

    #  ML prediction
    ml_result, confidence = check_url_ml(url)

    #  VirusTotal scan
    vt_result = scan_url_virustotal(url)

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)

    #  HARD PRIORITY LOGIC
    if malicious > 0:
        final_status = "malicious"
    elif suspicious > 0:
        final_status = "suspicious"
    elif ml_result == "phishing":
        final_status = "phishing"
    else:
        final_status = "clean"

    # Explainability (Rule-based)
    features = extract_features(url)
    explanation = explain_url(url, features)

    # Risk mapping
    risk_level = map_risk(confidence, final_status)

    return {
        "url": url,
        "ml_result": ml_result,
        "ml_confidence": confidence,
        "risk_level": risk_level,
        "explanation": explanation,
        "virustotal": vt_result,
        "final_status": final_status
    }
