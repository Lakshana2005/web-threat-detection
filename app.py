print(" RUNNING NEW APP.PY VERSION ")
from vt_client import scan_file_hash_virustotal_detailed

from utils.stages import (
    STAGE_RECEIVED,
    STAGE_HASHING,
    STAGE_SCANNING,
    STAGE_COMPLETE
)

from explainability.file_explainer import explain_file
from utils.risk_mapper import map_risk

from flask import Flask, request, jsonify
from flask_cors import CORS

from url_pipeline import final_url_verdict
from vt_client import scan_file_hash_virustotal
from file_scanner import generate_file_hash

app = Flask(__name__)
CORS(app)

app.config['TEMPLATES_AUTO_RELOAD'] = False
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

#  Global error handler
@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({
        "status": "error",
        "stage": "internal_error",
        "message": "Internal server error",
        "details": str(e)
    }), 500

# ===================== URL SCAN =====================

@app.route("/check_url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({
            "status": "error",
            "message": "URL is required"
        }), 400

    result = final_url_verdict(url)
    
    if result.get("error", False):
        return jsonify({
            "status": "error",
            "type": "url",
            "message": result.get("error_message", "Invalid URL"),
            "data": result
        }), 400 

    return jsonify({
        "status": "success",
        "type": "url",
        "stage": STAGE_COMPLETE,
        "message": "URL analyzed successfully",
        "data": result
    })

# ===================== MULTIPLE URL SCAN =====================

@app.route("/scan-multiple-urls", methods=["POST"])
def scan_multiple_urls():
    data = request.get_json() or {}
    urls = data.get("urls", [])
    
    if not isinstance(urls, list):
        return jsonify({
            "status": "error",
            "message": "URLs must be provided as a list"
        }), 400

    if len(urls) > 100:
        return jsonify({
            "status": "error",
            "message": "Maximum 100 URLs allowed per batch"
        }), 400

    results = []
    safe_count = 0
    phishing_count = 0
    invalid_count = 0

    for url in urls:
        verdict = final_url_verdict(url)
        
        if verdict.get("error", False):
            invalid_count += 1
            results.append({
                "url": url,
                "result": "INVALID",
                "error": verdict.get("error_message", "Invalid URL format"),
                "confidence": 0.0,
                "risk_level": "INVALID"
            })
            continue
        
        final_status = verdict.get("final_status", "unknown")

        if final_status.lower() == "clean":
            safe_count += 1
            label = "Safe"
        else:
            phishing_count += 1
            label = "Phishing" if final_status != "suspicious" else "Suspicious"

        results.append({
            "url": url,
            "result": label,
            "confidence": verdict.get("ml_confidence"),
            "risk_level": verdict.get("risk_level")
        })

    return jsonify({
        "status": "success",
        "type": "multiple_url",
        "total": len(urls),
        "valid": len(urls) - invalid_count,
        "invalid": invalid_count,
        "safe": safe_count,
        "phishing": phishing_count,
        "details": results
    })

# ===================== FILE SCAN =====================

@app.route("/scan_file", methods=["POST"])
def scan_file():

    current_stage = STAGE_RECEIVED

    if "file" not in request.files:
        return jsonify({
            "status": "error",
            "stage": current_stage,
            "message": "File is required"
        }), 400

    file = request.files["file"]

    current_stage = STAGE_HASHING
    file_hash = generate_file_hash(file.stream)

    try:
        current_stage = STAGE_SCANNING
        vt_result = scan_file_hash_virustotal(file_hash)

    except Exception as e:
        return jsonify({
            "status": "error",
            "stage": current_stage,
            "message": "VirusTotal service unavailable",
            "details": str(e)
        }), 503

    if vt_result.get("status") == "unknown":
        return jsonify({
            "status": "success",
            "type": "file",
            "stage": STAGE_COMPLETE,
            "message": "File not found in VirusTotal database",
            "data": {
                "file_name": file.filename,
                "sha256": file_hash,
                "final_status": "clean",
                "risk_level": "LOW ",
                "confidence": 0.85,
                "file_explanation": [
                    "File type appears benign",
                    "No known malware signatures detected",
                    "File hash not previously reported as malicious"
                ],
                "malware_type": None,
                "virustotal": vt_result
            }
        })

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    malware_type = vt_result.get("malware_type", "Unknown malware")

    confidence = min((malicious + suspicious) / 10, 1.0)

    final_status = "clean"
    if malicious > 0:
        final_status = "malicious"
    elif suspicious > 0:
        final_status = "suspicious"

    file_explanation = explain_file(vt_result)
    risk_level = map_risk(confidence, final_status)

    return jsonify({
        "status": "success",
        "type": "file",
        "stage": STAGE_COMPLETE,
        "message": "File scanned successfully",
        "data": {
            "file_name": file.filename,
            "malware_type": malware_type,
            "sha256": file_hash,
            "final_status": final_status,
            "risk_level": risk_level,
            "confidence": confidence,
            "file_explanation": file_explanation,
            "virustotal": vt_result
        }
    })

# ===================== MULTIPLE FILE SCAN =====================

@app.route("/scan-multiple-files", methods=["POST"])
def scan_multiple_files():

    if "files" not in request.files:
        return jsonify({
            "status": "error",
            "message": "Files are required"
        }), 400

    files = request.files.getlist("files")

    if len(files) > 20:
        return jsonify({
            "status": "error",
            "message": "Maximum 20 files allowed per batch"
        }), 400

    high_risk = []
    medium_risk = []
    low_risk = []

    for file in files:

        file_hash = generate_file_hash(file.stream)
        try:
            vt_result = scan_file_hash_virustotal(file_hash)
        except Exception as e:
            print(f"VirusTotal error for {file.filename}: {e}")
            low_risk.append({
                "file_name": file.filename,
                "sha256": file_hash,
                "risk_level": "UNKNOWN ",
                "confidence": 0.0,
                "malware_type": None,
                "error": "VirusTotal scan failed for this file"
            })
            continue 

        if vt_result.get("status") == "unknown":
            low_risk.append({
                "file_name": file.filename,
                "sha256": file_hash,
                "risk_level": "LOW ",
                "confidence": 0.0,
                "malware_type": None
            })
            continue

        malicious = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)

        confidence = min((malicious + suspicious) / 10, 1.0)

        final_status = "clean"
        if malicious > 0:
            final_status = "malicious"
        elif suspicious > 0:
            final_status = "suspicious"

        risk_level = map_risk(confidence, final_status)

        file_data = {
            "file_name": file.filename,
            "sha256": file_hash,
            "risk_level": risk_level,
            "confidence": confidence,
            "malware_type": vt_result.get("malware_type")
        }

        if "HIGH" in risk_level.upper():
            high_risk.append(file_data)
        elif "MEDIUM" in risk_level.upper():
            medium_risk.append(file_data)
        else:
            low_risk.append(file_data)

    return jsonify({
        "status": "success",
        "type": "multiple_file",
        "summary": {
            "High Risk Files": len(high_risk),
            "Medium Risk Files": len(medium_risk),
            "Low Risk Files": len(low_risk)
        },
        "high_risk_files": high_risk,
        "medium_risk_files": medium_risk,
        "low_risk_files": low_risk
    })

@app.route("/")
def home():
    return "Backend is running successfully"

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, threaded=True)
