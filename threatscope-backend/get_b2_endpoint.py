import requests
from requests.auth import HTTPBasicAuth

url = "https://api.backblazeb2.com/b2api/v3/b2_authorize_account"
auth = HTTPBasicAuth("7dace0c2eb40", "0059bf1cd108fa6db18a73b173b453ac65ee279036")
response = requests.get(url, auth=auth)
print(response.json())
