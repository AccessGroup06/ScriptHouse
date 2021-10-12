# @author Omar Hawwash, Aalborg University, Campus Copenhagen

import base64, json, requests

# ============================================================= #
#  VirusTotal API - automation for IP addresses                 #
#  - Asks for info regarding an IP address and                  #
#    how it's been flagged                                      #
# ============================================================= #

# Retrieving user input for the IP that will be scanned in this iteration
get_IP = input("Enter IP address for Scanning... ")

# API key for authentication with VirusTotal's API
api_key='57856d7e94768680c4d2378f9ecb8e4a2faa92889f55b42c487e5d1a982e5ab8'

# Required header for the GET request
headers = {'x-apikey': api_key}

# The IP we want to search through VirusTotal (this has the user input appended).
urltoVT = "https://www.virustotal.com/api/v3/ip_addresses/" + get_IP

# Sending request to the API with our IP address
r = requests.get((urltoVT),headers=headers)

# Print the result on-screen (for debug purposes)
#print(r.text)

# Load response from initial IP check into Python and parse JSON into FlaggedMalicious (how many times the IP is flagged as malicious) and FlaggedSuspicious

jsonformatted = json.loads(r.text)
flaggedMalicious = jsonformatted["data"]["attributes"]["last_analysis_stats"]["malicious"]
flaggedSuspicious = jsonformatted["data"]["attributes"]["last_analysis_stats"]["suspicious"]

# Now check for how many files the IP is communicating with

checkCommunicatingFiles = "https://www.virustotal.com/api/v3/ip_addresses/" + get_IP + "/communicating_files"

# Send a get request to receive all info from the API
r2 = requests.get((checkCommunicatingFiles), headers=headers)

# Print all info on-screen (for debug purposes)
#print(r2.text)

# Format the output so we can get the count of files VT reports its association with, and proceed to print it.

jsonformatcmfiles = json.loads(r2.text)
communicatingFiles = jsonformatcmfiles["meta"]["count"]
#print(communicatingFiles)

# Final prints as verdicts of the conducted research

print("The IP address is communicating with", communicatingFiles, "files.")

# Assumptious print: if the IP communicates with 100+ files, we warn the user it might be a botmaster
if communicatingFiles > 100:
    print("*** !WARNING! *** Since this IP is communicating with over 100 files, it might be the IP of a command-and-control center!")

# Prints about malicious and suspicious flags
print("This IP was flagged as malicious:", flaggedMalicious, "times!")
print("This IP was flagged as suspicious:", flaggedSuspicious, "times!")