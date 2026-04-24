import requests

response = requests.post(
    "http://127.0.0.1:5000/check_url",
    json={"url": "http://login-paypal-verification.com"}
)

print(response.json())
