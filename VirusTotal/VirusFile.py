# Modules that we need for interacting with the virustotal api
import requests, json, sys, os

from requests.models import Response

api_key = '57856d7e94768680c4d2378f9ecb8e4a2faa92889f55b42c487e5d1a982e5ab8'
url= "https://www.virustotal.com/api/v3/files"
headers = {'x-apikey': api_key}
#filepath = sys.path.append(os.path.realpath('F:\\GIT\\Repos\\StudentTasks\\VirusTotal\\filestoScan\\1.exe'))
files = {'file': open('F:\\GIT\\Repos\\StudentTasks\\VirusTotal\\filestoScan\\1.exe','rb')}
r = requests.post(url, files=files, headers=headers)
#print(r.text)
#print("Now, let's get the ID!")
jsonformatted = json.loads(r.text)
#print(jsonformatted["data"]["id"])
idfromVT = jsonformatted["data"]["id"]
urltoVT = "https://www.virustotal.com/api/v3/analyses/" + idfromVT
#print(urltoVT)
r2 = requests.get(urltoVT,headers=headers)

print(r2.text)

#print("Hello and welcome to the VirusTotal API Tool!")
#print("Through this tool you'll be able to submit a file in the filestoScan folder and check if the file is malicious.")
#print("If the file is flagged as malicious by 1 to 3 AVs it's considered potentially malicious.")
#print("If the file is flagged as malicious by 5 or more AVs, it's considered malicious.")
#print("Otherwise, it's considered as 'not malicious'.")

dangerousSubstring = "malicious"
mainString = r2.text

countString = mainString.count(dangerousSubstring)
print("The file is considered malicious by", countString, "antiviruses.")

if(countString) <= 0: 
    print("The file is not malicious")
elif(1 > countString <= 3):
    print("The file may be malicious")
elif(countString >= 5):
    print("The file is most likely malicious")
else:
    print("File may be corrupted or otherwise not readable. Please try again!") 
