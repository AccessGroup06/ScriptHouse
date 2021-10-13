import base64
import json
import requests
# ============================================================= #
#  VirusTotal Api - automation for URL                          #
#  - Asks for the URL and comes up with the results             #
# ============================================================= #

# Getting URL for Scannig
get_url = input("Enter URL for Scanning... ")

# Generating base 64 of the entered URL, required for vt api 
url_id = base64.urlsafe_b64encode("{}".format(get_url).encode()).decode().strip("=")
base64_Url = url_id

# Api key for authentication with vt api
api_key='57856d7e94768680c4d2378f9ecb8e4a2faa92889f55b42c487e5d1a982e5ab8'

# Required header for the GET reqest
headers = {'x-apikey': api_key}

# Sending request plus appending the base64 of the URL
r = requests.get("https://www.virustotal.com/api/v3/urls/{}".format(str(base64_Url)),headers=headers)
#print(r.text)

jsonformatted = json.loads(r.text)
flaggedMalicious = jsonformatted["data"]["attributes"]["last_analysis_stats"]["malicious"]
flaggedSuspicious = jsonformatted["data"]["attributes"]["last_analysis_stats"]["suspicious"]
print(flaggedMalicious)
# flaggedMalicious = mainString.count(findString)
print("The URL is considered malicious by", flaggedMalicious, "antiviruses.")

if(flaggedMalicious) <= 0: 
    print("Not malicious")
elif(1 > flaggedMalicious <= 3):
    print("URL might be malicious")
elif(flaggedMalicious >= 5):
    print("URL is malicious")
else:
    print("URL unreachable. Please try again later!")

# Example Test : https://www.csm-testcenter.org/download/malicious/index.html
# https://developers.virustotal.com/reference#url-object (For detail information)
