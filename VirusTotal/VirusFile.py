# @author Omar Hawwash, Aalborg University, Campus Copenhagen

# Modules that we need for interacting with the VirusTotal API
import requests, json, sys, os

from requests.models import Response

# The API key used by VirusTotal
api_key = '57856d7e94768680c4d2378f9ecb8e4a2faa92889f55b42c487e5d1a982e5ab8'

# The URL needed for file submission & other formalia regarding VirusTotal
url= "https://www.virustotal.com/api/v3/files"
headers = {'x-apikey': api_key}

# The full path to the file that you want to submit (REMEMBER TO CHANGE THE PATH)

files = {'file': open('F:\\GIT\\Repos\\StudentTasks\\VirusTotal\\filestoScan\\1.exe','rb')}

# Post the request to the VirusTotal API
r = requests.post(url, files=files, headers=headers)

# Formatting the JSON query into a Python dictionary
jsonformatted = json.loads(r.text)

# Retrieving the ID as a single variable from the JSON query
idfromVT = jsonformatted["data"]["id"]

# Appending the ID to the URL that will be sent to VirusTotal to retrieve analysis verdicts (concatenating the string of the URL + the ID)
urltoVT = "https://www.virustotal.com/api/v3/analyses/" + idfromVT

# This was for debugging reasons :-)
#print(urltoVT)

# Retrieve the info that relates to our specific file
r2 = requests.get(urltoVT,headers=headers)

# Print the full JSON response, which includes the assessments from all the AV's
print(r2.text)

# RULES for assessment
# If the file is flagged as malicious by 1 to 3 AVs it's considered potentially malicious.
# If the file is flagged as malicious by 5 or more AVs, it IS considered malicious.
# Otherwise, it's considered 'not malicious'.

# This is to get the info from the AVs that specifically have flagged the files as malicious, so we can use it for the counter in the end.
dangerousSubstring = "malicious"

# This is the full string of the JSON response, turned into a 'String', so we can search in its substrings.
mainString = r2.text

# How many times have we seen the word malicious in the full JSON response?
countString = mainString.count(dangerousSubstring)

# Print the verdicts

print("The file is considered malicious by", countString, "antiviruses.")

if(countString) <= 0: 
    print("The file is not malicious")
elif(1 > countString <= 3):
    print("The file may be malicious")
elif(countString >= 5):
    print("The file is most likely malicious")
else:
    print("File may be corrupted or otherwise not readable. Please try again!") 
