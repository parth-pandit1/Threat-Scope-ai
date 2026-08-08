import os
import sys
from dotenv import load_dotenv

load_dotenv()
redis_url = os.environ.get("REDIS_URL")
if not redis_url:
    print("No REDIS_URL found in .env")
    sys.exit(1)

print(f"Starting rq worker with REDIS_URL={redis_url}")
os.system(f"rq worker default --url {redis_url} --worker-class rq.worker.SimpleWorker")
