import requests
import json

base_url = "http://127.0.0.1:8000/api"
print("--- Health Check ---")
try:
    resp = requests.get(f"{base_url}/health")
    print(f"Status: {resp.status_code}")
    print(json.dumps(resp.json(), indent=2))
except Exception as e:
    print(e)

print("\n--- File Scan ---")
try:
    with open("requirements.txt", "rb") as f:
        resp = requests.post(f"{base_url}/scan/file", files={"file": f})
    print(f"Status: {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except:
        print(resp.text)
except Exception as e:
    print(e)

print("\n--- URL Scan ---")
try:
    resp = requests.post(f"{base_url}/scan/url", json={"url": "https://example.com"})
    print(f"Status: {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except:
        print(resp.text)
except Exception as e:
    print(e)

print("\n--- Stats ---")
try:
    resp = requests.get(f"{base_url}/stats")
    print(f"Status: {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except:
        print(resp.text)
except Exception as e:
    print(e)
