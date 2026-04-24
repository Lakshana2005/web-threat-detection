def explain_file(vt_stats):
    explanations = []

    malicious = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)
    harmless = vt_stats.get("harmless", 0)
    undetected = vt_stats.get("undetected", 0)

    if malicious > 0:
        explanations.append(
            f"{malicious} antivirus engine(s) flagged this file as malicious"
        )

    if suspicious > 0:
        explanations.append(
            f"{suspicious} engine(s) reported suspicious behavior"
        )

    if malicious == 0 and suspicious == 0:
        explanations.append(
            "No antivirus engines detected malicious behavior"
        )

    if undetected > 20:
        explanations.append(
            "Many engines could not classify this file (low reputation)"
        )

    return explanations
