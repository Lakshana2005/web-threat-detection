from feature_extraction import extract_features

test_urls = [
    "https://www.google.com",
    "http://secure-google-login.xyz/verify",
    "https://bit.ly/3x9Qp2",
    "http://192.168.1.10/login"
]

for url in test_urls:
    print("\nURL:", url)
    features = extract_features(url)
    for k, v in features.items():
        print(f"{k}: {v}")
