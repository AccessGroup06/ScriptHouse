# Modules that we need for interacting with the virustotal api
import requests,json

from requests.models import Response

api_key = '57856d7e94768680c4d2378f9ecb8e4a2faa92889f55b42c487e5d1a982e5ab8'
url= "https://www.virustotal.com/api/v3/files"
headers = {'x-apikey': api_key}
files = {'file': open('/home/ohawwash/Documents/AAU/StudentTasks/VirusTotal/filestoScan/1.exe','rb')}
r = requests.post(url, files=files, headers=headers)
#print(r.text)
r2 = requests.get("https://www.virustotal.com/api/v3/analyses/MDI4MjE1YjZhODQ0M2IxYzgyZjFjZDk0ZTk4ZWFhYTc6MTYzMjIyODAyNQ==",headers=headers)

print("Hello and welcome to the VirusTotal API Tool!")
print("Through this tool you'll be able to submit a file in the filestoScan folder and check if the file is malicious.")
print("If the file is flagged as malicious by 1 to 3 AVs it's considered potentially malicious.")
print("If the file is flagged as malicious by 5 or more AVs, it's considered malicious.")
print("Otherwise, it's considered as 'not malicious'.")

dangerousSubstring = "malicious"
mainString = r2.text

countString = mainString.count(dangerousSubstring)
print("The file is considered malicious by", countString, "antiviruses.")

if(countString) <= 0: 
    print("Not malicious")
elif(1 > countString <= 3):
    print("File may be malicious")
elif(countString >= 5):
    print("File is malicious")
else:
    print("File may be corrupted or otherwise not readable. Please try again!") 

#if dangerousSubstring in mainString: 
#    print("**** File is dangerous!")
#else:
#    print("*** File is safe! ****")
#print(r2.text)
#json_response = json.loads(Response.content)
#print(json_response)