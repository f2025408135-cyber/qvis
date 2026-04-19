import requests

r = requests.get('http://localhost:8000/')
print("nonce in text: ", "nonce=" in r.text)
print("CSP header: ", r.headers.get("content-security-policy"))
