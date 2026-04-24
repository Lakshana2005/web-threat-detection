import sys
import os
sys.path.append(os.path.dirname(__file__))

from url_checker import check_url_ml

# Test the same URL multiple times
test_url = "http://secure-google-login.xyz/verify"

print("Testing model consistency...")
print(f"URL: {test_url}")
print("-" * 50)

for i in range(5):
    result, confidence = check_url_ml(test_url)
    print(f"Attempt {i+1}: {result} (confidence: {confidence:.2%})")
