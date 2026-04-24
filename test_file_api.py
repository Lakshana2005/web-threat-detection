import requests
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE_PATH = os.path.join(BASE_DIR, "sample.txt")

files = {
    "file": open(FILE_PATH, "rb")
}

response = requests.post(
    "http://127.0.0.1:5000/scan_file",
    files=files
)

print(response.json())
