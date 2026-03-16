import requests

url = "https://control.msg91.com/api/v5/flow"

headers = {
    "accept": "application/json",
    "authkey": "497136AJYmC4jOS69aeafa0P1",
    "content-type": "application/json"
}

payload = {
    "template_id": "69b7b275cc3c7feb090a6893",
    "recipients": [
        {
            "mobiles": "917569085771",
            "VAR1": "1234"
        }
    ]
}

response = requests.post(url, json=payload, headers=headers)

print(response.status_code)
print(response.text)