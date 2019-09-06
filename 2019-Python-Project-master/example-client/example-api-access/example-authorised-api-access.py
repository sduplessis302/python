import urllib.request
import json
import base64

url = "http://cs302.kiwi.land/api/report"

#STUDENT TO UPDATE THESE...
username = "sdup751"
password = "sduplessis302_513954215"

#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))
headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type': 'application/json; charset=utf-8',
}

payload = {
    # STUDENT TO COMPLETE THIS...
    "connection_address": "1",
    "connection_location": "http://cs302.kiwi.land/api/report"
}

#STUDENT TO COMPLETE:
#1. convert the payload into json representation,
#2. ensure the payload is in bytes, not a string
#3. pass the payload bytes into this function

data_str = json.dumps(payload)
json_data = data_str.encode('utf-8')

try:
    req = urllib.request.Request(url, headers=headers)
    response = urllib.request.urlopen(req, data=json_data)
    data = response.read()  # read the received bytes
    encoding = response.info().get_content_charset('utf-8')  #load encoding if possible (default to utf-8)
    response.close()
except urllib.error.HTTPError as error:
    print(error.read())
    exit()

JSON_object = json.loads(data.decode(encoding))
print(JSON_object)

