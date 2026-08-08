from minio import Minio

key_id = "7dace0c2eb40"
app_key = "0059bf1cd108fa6db18a73b173b453ac65ee279036"

regions = ["s3.us-west-000.backblazeb2.com", "s3.us-west-001.backblazeb2.com", 
           "s3.us-west-002.backblazeb2.com", "s3.us-west-003.backblazeb2.com", 
           "s3.us-west-004.backblazeb2.com", "s3.us-east-005.backblazeb2.com", 
           "s3.eu-central-003.backblazeb2.com"]

found = None
for endpoint in regions:
    client = Minio(endpoint, access_key=key_id, secret_key=app_key, secure=True)
    try:
        client.list_buckets()
        print(f"Success! Endpoint is {endpoint}")
        found = endpoint
        break
    except Exception as e:
        pass

if not found:
    print("Could not find the correct B2 endpoint.")
