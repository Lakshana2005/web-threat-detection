# explainability/url_explainer.py - REPLACE ENTIRE FILE

from urllib.parse import urlparse
import re

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", 
    "account", "bank", "confirm", "signin", "payment",
    "password", "credential", "auth", "wallet", "paypal",
    "ebay", "appleid", "icloud", "outlook", "office365"
]

CLOUD_HOSTING_PROVIDERS = [
    "appspot", "cloud", "firebase", "herokuapp",
    "aws", "azure", "gcp", "000webhost", "freehost"
]

def explain_url(url, features):
    explanations = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # PHISHING DETECTION RULES (PRIORITY ORDER)
    
    # 1️⃣ IP address - STRONG phishing signal
    if features.get("has_ip") == 1:
        explanations.append("🚨 Uses IP address instead of domain name (common in phishing)")
    
    # 2️⃣ Suspicious keywords in path - VERY STRONG signal
    path_keywords = []
    for word in SUSPICIOUS_WORDS:
        if word in path:
            path_keywords.append(word)
    if path_keywords:
        explanations.append(f"⚠️ Phishing keyword in URL path: {', '.join(path_keywords[:3])}")
    
    # 3️⃣ Suspicious keywords in domain
    domain_keywords = []
    for word in SUSPICIOUS_WORDS:
        if word in domain:
            domain_keywords.append(word)
    if domain_keywords:
        explanations.append(f"⚠️ Suspicious keyword in domain: {', '.join(domain_keywords[:2])}")
    
    # 4️⃣ Shortened URL
    if features.get("is_shortened") == 1:
        explanations.append("🔗 Shortened URL - hides real destination")
    
    # 5️⃣ No HTTPS
    if features.get("uses_https") == 0:
        explanations.append("🔓 No HTTPS encryption - data not secure")
    
    # 6️⃣ Too many subdomains
    if features.get("num_subdomains", 0) > 2:
        explanations.append(f"📌 Multiple subdomains ({features['num_subdomains']}) - obfuscation tactic")
    
    # 7️⃣ URL too long
    if len(url) > 100:
        explanations.append("📏 Excessive URL length - hides malicious intent")
    
    # 8️⃣ Many special characters
    if features.get("count_special_chars", 0) > 10:
        explanations.append(f"🔣 Many special characters ({features['count_special_chars']}) - URL manipulation")
    
    # 9️⃣ Cloud hosting
    for provider in CLOUD_HOSTING_PROVIDERS:
        if provider in domain:
            explanations.append("☁️ Hosted on free/cloud platform (frequently abused)")
            break
    
    # 🔟 @ symbol
    if features.get("has_at_symbol") == 1:
        explanations.append("📧 '@' symbol - credential harvesting pattern")
    
    # 💡 FOR PHISHING DETECTIONS - ENSURE REASONS EXIST
    if features.get("is_phishing_ml", 0) == 1 or features.get("final_status") == "phishing":
        # If no strong reasons found, add generic phishing reason
        has_strong_reason = False
        strong_signals = ["IP address", "Phishing keyword", "Suspicious keyword", 
                         "Shortened URL", "@' symbol", "Multiple subdomains"]
        
        for reason in explanations:
            if any(signal in reason for signal in strong_signals):
                has_strong_reason = True
                break
        
        if not has_strong_reason:
            # Add specific reason based on features
            if features.get("count_digits", 0) > 5:
                explanations.append("🔢 Unusual number of digits - automated domain generation")
            elif features.get("path_length", 0) > 50:
                explanations.append("📁 Long suspicious path - mimics legitimate login pages")
            else:
                explanations.append("🎣 URL pattern matches known phishing techniques")
    
    # Final fallback
    if not explanations:
        explanations.append("✅ No strong phishing indicators detected")
    
    return explanations
