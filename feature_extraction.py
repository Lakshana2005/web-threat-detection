import re
from urllib.parse import urlparse
import tldextract

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "signin", "payment"
]

def has_ip(url):
    return bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url))

def is_shortened(url):
    return any(short in url for short in SHORTENERS)

def count_special_chars(url):
    return sum(not c.isalnum() for c in url)

def extract_features(url):
    features = {}

    parsed = urlparse(url)
    ext = tldextract.extract(url)

    features["url_length"] = len(url)
    features["hostname_length"] = len(parsed.netloc)
    features["path_length"] = len(parsed.path)

    features["count_dots"] = url.count(".")
    features["count_hyphens"] = url.count("-")
    features["count_digits"] = sum(c.isdigit() for c in url)
    features["count_special_chars"] = count_special_chars(url)

    features["has_at_symbol"] = 1 if "@" in url else 0
    features["has_ip"] = 1 if has_ip(url) else 0
    features["is_shortened"] = 1 if is_shortened(url) else 0
    features["uses_https"] = 1 if parsed.scheme == "https" else 0

    for word in SUSPICIOUS_WORDS:
        features[f"has_{word}"] = 1 if word in url.lower() else 0

    features["num_subdomains"] = ext.subdomain.count(".") + (1 if ext.subdomain else 0)

    return features
