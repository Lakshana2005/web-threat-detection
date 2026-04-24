# test_url_validation.py

import requests
import json

# Test various invalid inputs
test_inputs = [
    "",                    # Empty
    "   ",                 # Whitespace
    "cat",                 # Random word
    "hello world",         # Space in URL
    "ftp://example.com",   # Wrong protocol
    "http://",             # Incomplete
    "https://",            # Incomplete
    "justtext",            # No domain
    "http://",             # Missing domain
    ".com",                # Just TLD
    "http://.com",         # Invalid domain
    "http://invalid@domain", # Invalid character
]

print("=" * 60)
print("TESTING URL VALIDATION")
print("=" * 60)

for test_input in test_inputs:
    print(f"\n🔍 Testing: '{test_input}'")
    
    response = requests.post(
        "http://127.0.0.1:5000/check_url",
        json={"url": test_input}
    )
    
    result = response.json()
    print(f"Status Code: {response.status_code}")
    print(f"Status: {result.get('status')}")
    
    if response.status_code == 400:
        print(f"❌ Error: {result.get('message')}")
        if 'data' in result:
            print(f"Details: {result['data'].get('explanation', [''])[0]}")
    else:
        print(f"✅ Result: {result.get('data', {}).get('final_status')}")
    
print("\n" + "=" * 60)
print("TESTING VALID URLs")
print("=" * 60)

valid_urls = [
    "https://google.com",
    "http://example.org",
    "google.com",  # Should auto-add http://
    "www.github.com",  # Should work
    "https://stackoverflow.com/questions/ask",
]

for test_input in valid_urls:
    print(f"\n🔍 Testing: '{test_input}'")
    
    response = requests.post(
        "http://127.0.0.1:5000/check_url",
        json={"url": test_input}
    )
    
    result = response.json()
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = result.get('data', {})
        print(f"✅ Normalized URL: {data.get('url')}")
        print(f"✅ Status: {data.get('final_status')}")
    else:
        print(f"❌ Error: {result.get('message')}")