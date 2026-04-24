def map_risk(confidence, final_status):
    confidence_pct = int(confidence * 100)

    if final_status in ["malicious", "phishing"]:
        if confidence_pct >= 80:
            return "HIGH 🔴"
        elif confidence_pct >= 50:
            return "MEDIUM 🟡"
        else:
            return "LOW 🟢"

    if final_status == "suspicious":
        return "MEDIUM 🟡"

    return "LOW 🟢"
