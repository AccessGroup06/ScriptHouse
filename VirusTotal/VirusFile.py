# Modules that we need for interacting with the VirusTotal API
import requests, json, sys, os

from requests.models import Response

# The API key used by VirusTotal
api_key = 'YOUR API KEY GOES HERE'

# The URL needed for file submission and other formalia regarding VirusTotal
url= "https://www.virustotal.com/api/v3/files"
headers = {'x-apikey': api_key}

# The full path to the file that you want to submit - this is user input 
# for the path - for example: (Windows: C:\Users\Username\folder - Linux: /home/username/folder)
filepath = input("Please enter the FULL path to your file...")

files = {'file': open(filepath,'rb')}

# Post the request to the VirusTotal API
r = requests.post(url, files=files, headers=headers)

# Formatting the JSON query into a Python dictionary
jsonformatted = json.loads(r.text)

# Retrieving the ID as a single variable from the JSON query
idfromVT = jsonformatted["data"]["id"]

# Appending the ID to the URL that will be sent to VirusTotal to retrieve analysis verdicts (concatenating the string of the URL + the ID)
urltoVT = "https://www.virustotal.com/api/v3/analyses/" + idfromVT

# This was for debugging reasons :-)
print(urltoVT)

# Retrieve the info that relates to our specific file
r2 = requests.get(urltoVT,headers=headers)

# Print the full JSON response, which includes the assessments from all the AV's
#print(r2.text)

# Let's only get data from Kaspersky (or an AV of our choice) -- change the last part of the tuple if you want a different AV :) /OH
ourAntivirus = jsonformatted["data"]["results"]["Kaspersky"]

# Give us the category that our antivirus deems this to be:
avfindingsCat = ourAntivirus["category"]

# Give us the result from this AV:
avfindingsResult = ourAntivirus["result"]

# Give us the method result from this AV:
avfindingsMethod = ourAntivirus["method"]

# Parse the JSON response including the assessments into Python so we can retrieve the malicious stat later.
jsonformatted = json.loads(r2.text)

print("KasperSky has deemed this file to be:\n") # Remember to change the AV name in this hard-coded print, if needed :)
print("Under the category: ", avfindingsCat)
print("The result of the scan through this AV was: ", avfindingsResult)
print("The method for this file scan is: ", avfindingsMethod)

# How many times have we seen the word malicious in the full JSON response? (Retrieve malicious 'stat')
flaggedMalicious = jsonformatted["data"]["attributes"]["stats"]["malicious"]

# RULES for assessment
# If the file is flagged as malicious by 1 to 3 AVs it's considered potentially malicious.
# If the file is flagged as malicious by 5 or more AVs, it IS considered malicious.
# Otherwise, it's considered 'not malicious'.

# Print the verdicts

print("The file is considered malicious by", flaggedMalicious, "antiviruses.")

if(flaggedMalicious) <= 0: 
    print("The file is not malicious.")
elif(1 > flaggedMalicious <= 3):
    print("The file may be malicious.")
elif(flaggedMalicious >= 5):
    print("The file is most likely malicious.")
#else:
#    print("File may be corrupted or otherwise not readable. Please try again!") 
