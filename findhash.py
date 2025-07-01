import sys
import requests
import json

debug = False

def restCall(method, url, **parts):
    if debug:
        print ("Attempting ", method, url)
    response = getattr(requests, method.lower())(url, **parts) 

    if debug:
        print(f"Status Code: {response.status_code}")
    #print (response.text)
    try:
        response_json = json.loads(response.text)
    except:
        if debug:
            print("Bad JSON received:")
            print (response.text)
    else:
        if debug:
            print (json.dumps(response_json, indent=2))
    return response

def readkey(filename):
    try:
        with open("keys/"+filename, 'r', encoding='utf-8') as file:
            key = file.read()
            return key
    except FileNotFoundError:
        print("Error: Unable to read file: " + filename)
    except Exception as e:
        print(f"An error occurred: {e}")

try:
    hashvalue = sys.argv[1]
except:
    print(f"Please pass hash value on the command-line")
    exit()

malwarebazaarauthkey = readkey ("malwarebazaar.authkey")
response = restCall ('POST', 'https://mb-api.abuse.ch/api/v1/', headers = {'Auth-Key': malwarebazaarauthkey}, data = {'query': 'get_info', 'hash': hashvalue})
if (response.status_code == 200):
    data = json.loads(response.text)
    print ("Malware Bazaar: " + data["query_status"])
else:
    print ("Bad response from Malware Bazaar")

hybridanalysisapikey = readkey ("hybridanalysis.apikey")
response = restCall ('GET', 'https://hybrid-analysis.com/api/v2/search/hash?hash='+hashvalue, headers = {'api-key': hybridanalysisapikey, 'accept': 'application/json'})
if (response.status_code == 200):
    print ("Hybrid Analysis: Found")
elif (response.status_code == 404):
    print ("Hybrid Analysis: Not Found")
else:
    print ("Bad response from Hybrid Analysis")
    
virustotalapikey = readkey ("virustotal.apikey")
response = restCall ('GET', 'https://www.virustotal.com/api/v3/files/'+hashvalue, headers = {'x-apikey': virustotalapikey, 'accept': 'application/json'})
if (response.status_code == 200):
    print ("VirusTotal: Code 200")
elif (response.status_code == 429):
    print ("VirusTotal: Quota exceeded")
else:
    print ("Bad response from Virus Total")

virusexchangeapikey = readkey ("virusexchange.apikey")
response = restCall ('GET', 'https://virus.exchange/api/samples/'+hashvalue, headers = {'Authorization': "Bearer " + virusexchangeapikey, 'accept': 'application/json'})
if (response.status_code == 200):
    print ("Virus Exchange: Found")
elif (response.status_code == 404):
    print ("Virus Exchange: Not Found")
else:
    print ("Bad response from Virus Exchange")

polyswarmapikey = readkey ("polyswarm.apikey")
response = restCall ('GET', 'https://api.polyswarm.network/v3/search/hash/sha256?hash='+hashvalue, headers = {'Authorization': polyswarmapikey})
if (response.status_code == 200):
    print ("PolySwarm: Found")
elif (response.status_code == 204):
    print ("PolySwarm: Not Found")
else:
    print ("Bad response from PolySwarm")