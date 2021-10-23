# This tool allows you to scan IP addresses on Shodan, as well as find IP addresses running on services, using Shodan's API.

import shodan

# Our API key for Shodan
api = shodan.Shodan('BRsAzZbv53PDXVavWZPZL5fMbVnnDlcd')

# ** Look up an IP using the Shodan API
def lookupIP():

    try:
        searchthisIP = input("Enter the IP... ")

        # If you want the program to print all data about the IP, answer 'yes' or 'y' - otherwise it won't. [DEBUG]
        doYouWantMeToTalk = input("Do you want me to talk? Y/N? \n")
        print('')

        # This sends the IP to the Shodan API so we can retrieve info about the IP.
        ipinfo = api.host(searchthisIP)

        # Print the entire response from the API [DEBUG]
        #print(ipinfo) 
        
        # If user says yes initially
        if doYouWantMeToTalk.find("N") == -1:
            # Prints info relevant to this IP:
            print("IP address: ", searchthisIP, "\n")
            print("Country code: ", ipinfo["country_code"], "\n")
            print("Region code: ", ipinfo["region_code"], "\n")
            print("City: ", ipinfo["city"], "\n")
            print("Latitude: ", ipinfo["latitude"], "\n")
            print("Longitude: ", ipinfo["longitude"], "\n")
            print("*** META INFO: ***", "\n")
            print("ISP: ", ipinfo["isp"], "\n")
            print("Organization: ", ipinfo["org"], "\n")
            print("Host name(s): ", ipinfo["hostnames"], "\n")

        else: 
            # If user says 'no':
            print("OK, I'll be quiet!")

    # If we encounter any API issues (capacity exceeded or 'this is a premium feature')            
    except shodan.APIError as e:
        print('Uh-oh! {}'.format(e))


# ** Find potentially vulnerable IPs running a certain service
def runningHosts():
    try:
            # Search Shodan for IPs running a certain service
            # The user inputs the service they'd like to search for
            searchForThis = input("Which service would you like to search for? ")
            # The service is then searched for using the Shodan API.
            results = api.search(searchForThis)

            # Show the results (quite self-explanatory. -- you can add more to this list if you'd like (check https://developer.shodan.io/api)) - 
            print('Results found: {}'.format(results['total']))
            for result in results['matches']:
                    print('IP: {}'.format(result['ip_str']))
                    print("Organization: {}".format(result['org']))
                    print("ISP: {}".format(result['isp']))
                    print("Hostnames: {}".format(result['hostnames']))
                    print("Domain(s): {}".format(result['domains']))
                    print("Operating system: {}".format(result['os']))
                    print("Port: {}".format(result['port']))
                    print("ASN: {}".format(result['asn']))
                    
                    # TO BE DISCARDED (maybe) - filters product (but this is already in data so not sure how useful this is) /OH
                    # Find product string (e.g. 'Nginx' & print it if it exists)
                    #productstr = result['product']
                    #if productstr.find(searchForThis) != -1:
                    #    print("Product: {}".format(result['product']))
                    #else: 
                    #    print("No info found for product.")

                    # Let us know if it's a 404 :) [and if it isn't, print out the related data]
                    if result['data'].find("404 Not Found") != -1:
                        print("404: YES")
                    else: 
                        print("404: NO")
                        print(result['data'])
                    print('')
    except shodan.APIError as e:
            print('Uh-oh! Error with the API... {}'.format(e))
    except KeyError as z:
            print('???', z)

# ** MAIN FUNCTION
def main():
    print("Welcome to the Shodan API tool!")
    print("What would you like to do?")
    print('')
    print("[1] Look up an IP using Shodan")
    print("[2] Search for potentially vulnerable IP addresses running a certain service")
    print('')

    # 1 and 2 are acceptable inputs as they launch method launchIP() and runningHosts() respectively.
    # Any other input will cause the program to terminate
    startinput = input("Enter the number of the tool you'd like to make use of: ")
    print('')
    if startinput == "1":
        lookupIP()
    elif startinput == "2":
        runningHosts()
    else: 
        print("Invalid input. Program terminating...")
        exit(0)

# ** Main method runner 
if __name__ == "__main__":
    main()

