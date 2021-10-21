# @author Omar Hawwash, Aalborg University, Campus Copenhagen

import base64, json, requests, random, os
from datetime import datetime

# ============================================================= #
#  VirusTotal API - automation for IP addresses                 #
#  - Asks for info regarding an IP address and                  #
#    how it's been flagged                                      #
# ============================================================= #

# This allows us to write tuple strings (so a string with, say, a number, into the file & is referenced when appending info to the file about comm. files, malicious & susp. flags)
def convertTuple(tup):
    st = ''.join(map(str, tup))
    return st

# File input from user with IP addresses separated by commas. Example file is provided in the same path as this file (see "ExampleInput.txt").
# for the path - for example: (Windows: C:\Users\Username\folder - Linux: /home/username/folder)
filepath = input("Please enter the FULL path to your file...")

# Set input and output file parameters
inputfile = open(filepath,'r')
scanThisIP = inputfile.readline()
splits = scanThisIP.split(",")
suffix = random.randint(0,9999)

# Currently, this program writes to a file called OUTPUT-<random integer>.txt. You can check which one is the newest...
# ... through the 'latest modified' metainfo on your OS for that file.

tempfilename = "OUTPUT-", suffix, ".txt"
filename = convertTuple(tempfilename)
createoutputfile = open(filename, "x")
outputfile = open(filename, "a")

# Iterator that reads through the file IP by IP and runs it through our scanner, then appends to file (in formatted manner)
iterator = 0
for ip in splits:
    currentIP = splits[iterator]
    temp = "\n*** \nIP address: ", currentIP, "\n"
    thisIP = convertTuple(temp)
    outputfile.write(thisIP)
    print(currentIP)
    get_IP = currentIP
    iterator = iterator + 1

# Which IP is it getting through? [DEBUG]
#get_IP = scanThisIP
#print(get_IP)

# API key for authentication with VirusTotal's API
    api_key='57856d7e94768680c4d2378f9ecb8e4a2faa92889f55b42c487e5d1a982e5ab8'

# Required header for the GET request
    headers = {'x-apikey': api_key}

# The IP we want to search through VirusTotal (this has the user input appended).
    urltoVT = "https://www.virustotal.com/api/v3/ip_addresses/" + get_IP

# Sending request to the API with our IP address
    r = requests.get((urltoVT),headers=headers)

# Print the result on-screen [DEBUG]
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


    ipcomm = "\nThe IP address is communicating with ", communicatingFiles, " files."
    str_ipcomm = convertTuple(ipcomm)
    outputfile.write(str_ipcomm)
    # Assumptious print: if the IP communicates with 100+ files, we warn the user it might be a botmaster
    if communicatingFiles > 100:
        warning = "\n*** !WARNING! *** Since this IP is communicating with over 100 files, it might be the IP of a command-and-control center!"
        outputfile.write(warning)

    # Prints about malicious and suspicious flags
    flagMalicious = "\nThis IP was flagged as malicious: ", flaggedMalicious, " times!"
    str_flagmalicious = convertTuple(flagMalicious)
    outputfile.write(str_flagmalicious)
    flagSuspicious = "\nThis IP was flagged as suspicious: ", flaggedSuspicious, " times! \n"
    str_flagsuspicious = convertTuple(flagSuspicious)
    outputfile.write(str_flagsuspicious)

# Close the file and print in the console that we're all done.
outputfile.close()
print("Done analyzing IP's!")