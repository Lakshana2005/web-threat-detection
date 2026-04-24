import requests
import time

API_KEY = "399fffc3687d3277cf580b2a5f2e9cf67d2df9c401ce139c8681371a71aaf11f"

BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": API_KEY
}

def scan_url_virustotal(url):
    submit_url = f"{BASE_URL}/urls"

    response = requests.post(
        submit_url,
        headers=HEADERS,
        data={"url": url}
    )

    if response.status_code != 200:
        return {"error": "VirusTotal URL submission failed"}

    analysis_id = response.json()["data"]["id"]

    # Wait for analysis
    time.sleep(3)

    report_url = f"{BASE_URL}/analyses/{analysis_id}"
    report = requests.get(report_url, headers=HEADERS)

    stats = report.json()["data"]["attributes"]["stats"]
    return stats

def scan_file_hash_virustotal(file_hash):
    url = f"{BASE_URL}/files/{file_hash}"

    response = requests.get(url, headers=HEADERS)

    if response.status_code != 200:
        return {"status": "unknown"}

    data = response.json()["data"]["attributes"]

    # ===================== STATS =====================
    stats = data.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    # ===================== THREAT CLASSIFICATION =====================
    malware_type = "Unknown"

    try:
        classification = data.get("popular_threat_classification", {})

        # Get threat category (Trojan, Worm, etc.)
        categories = classification.get("threat_category", [])
        if categories:
            malware_type = categories[0].get("value", "Unknown")

        # If no category found, try threat name
        names = classification.get("popular_threat_name", [])
        if malware_type == "Unknown" and names:
            malware_type = names[0].get("value", "Unknown")

    except Exception as e:
        print("Threat classification extraction failed:", e)
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "malware_type": malware_type
    }

def scan_file_hash_virustotal_detailed(file_hash):
    url = f"{BASE_URL}/files/{file_hash}"

    response = requests.get(url, headers=HEADERS)

    if response.status_code != 200:
        return {"status": "unknown"}

    data = response.json()["data"]["attributes"]

    stats = data.get("last_analysis_stats", {})

    # Extract malware family from VT
    threat_info = data.get("popular_threat_classification", {})
    threat_names = threat_info.get("popular_threat_name", [])

    malware_family = None

    if threat_names:
        malware_family = threat_names[0].get("value")

    return {
        "stats": stats,
        "malware_family": malware_family
    }
