import requests
import json
import time

base_url = "http://127.0.0.1:8000/api"

print("\n--- 1. Health Check ---")
try:
    resp = requests.get(f"{base_url}/health")
    print(f"Status: {resp.status_code}")
    print(json.dumps(resp.json(), indent=2))
except Exception as e:
    print(e)

print("\n--- 2. Register Test User ---")
auth_token = None
try:
    payload = {"email": "test@example.com", "password": "password123"}
    resp = requests.post(f"{base_url}/auth/register", json=payload)
    print(f"Status: {resp.status_code}")
    
    if resp.status_code == 400 and "already exists" in resp.text:
        print("User already exists, attempting login...")
        resp = requests.post(f"{base_url}/auth/login", json=payload)
        print(f"Login Status: {resp.status_code}")
        
    try:
        data = resp.json()
        print(json.dumps(data, indent=2))
        if "access_token" in data:
            auth_token = data["access_token"]
        elif "api_key" in data:
            auth_token = data["api_key"]
    except:
        print(resp.text)
except Exception as e:
    print(e)

print("\n--- 3. Submit File Scan ---")
scan_id = None
if auth_token:
    if auth_token.startswith("ts_"):
        headers = {"x-api-key": auth_token}
    else:
        headers = {"Authorization": f"Bearer {auth_token}"}
    try:
        with open("requirements.txt", "rb") as f:
            resp = requests.post(f"{base_url}/scan/file", headers=headers, files={"file": f})
        print(f"Status: {resp.status_code}")
        try:
            data = resp.json()
            print(json.dumps(data, indent=2))
            if "job_id" in data:
                scan_id = data["job_id"]
        except:
            print(resp.text)
    except Exception as e:
        print(e)
else:
    print("Skipping file scan (no auth token).")

print("\n--- 4. Poll Scan Results ---")
if scan_id:
    for _ in range(15):
        time.sleep(3)
        resp = requests.get(f"{base_url}/scan/{scan_id}", headers=headers)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"Scan status: {data.get('status')}")
            if data.get('status') in ('completed', 'failed'):
                print(json.dumps(data, indent=2))
                break
        else:
            try:
                print(json.dumps(resp.json(), indent=2))
            except:
                print(resp.text)
            break
else:
    print("Skipping polling (no scan ID).")
