# import module
import requests
import sys
import builtwith

# set url

url = "http://"+sys.argv[1]+"/admin"

def url_ok(site):
	# exception block
	try:
		# pass the url into
		# request.hear
		response = requests.head(site)
		# check the status code
		if response.status_code != 404:
			return True
		else:
			return False
	except requests.ConnectionError as e:
		return e

def admin(url):
        websitecheck1 = builtwith.parse(url)
        return(websitecheck1)

print(url)
if url_ok(url) == True:
    print("site bestaat, testing for /admin")  
    print(admin(url))
else:
    print("site bestaat niet")