
import requests  
import json
api_key = '57856d7e94768680c4d2378f9ecb8e4a2faa92889f55b42c487e5d1a982e5ab8'
url= "https://www.virustotal.com/api/v3/files"
headers = {'x-apikey': api_key}
files = {'file': open('\\Users\\its_a\\Desktop\\VirusTotal\\filestoScan\\1.exe','rb')}
r = requests.post(url, files=files, headers=headers)
print(r.text)
r2 = requests.get("https://www.virustotal.com/api/v3/analyses/MDI4MjE1YjZhODQ0M2IxYzgyZjFjZDk0ZTk4ZWFhYTc6MTYzMjIyODAyNQ==",headers=headers)
print(r2.text)