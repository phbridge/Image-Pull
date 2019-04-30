# Title
# Image Pull
#
# Language
# Python 3.5
#
# Description
# This script will take a Website username and password combination along with a userID (numerical) or username in
# phase 2. It will then discover all photos from that username. It will create a new directory with the username/ID
# and proceed to download the full size full quality version of the image.
#
# Contacts
# Phil Bridges - phbridge@cisco.com
#
# EULA
# This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges 
# with a varity of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and 
# arrangements. Until provison of alcohol or baked goodies your on your own but there is no rocket sciecne 
# involved so dont panic too much. To accept this EULA you must include the correct flag when running the script. 
# If this script goes crazy wrong and breaks everything then your also on your own and Phil will not accept any 
# liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held 
# responsable for its use or if it goes bad, nor can Cisco make any profit from this script. Phil can profit 
# from this script but will not assume any liability. Other than the boaring stuff please enjoy and plagerise 
# as you like (as I have no ways to stop you) but common curtacy says to credit me in some way. 
# [see above comments on Beer, Wine, Steak and Greggs.].
#
# Version Control               Comments
# Version 0.01 Date 13/12/16     Inital draft
#
# Version 6.9 Date xx/xx/xx     Took over world and actuially got paid for value added work....If your reading this approach me on linkedin for details of weekend "daily" rate
# Version 7.0 Date xx/xx/xx     Note to the Gaffer - if your reading this then the above line is a joke only :-)
#
# ToDo *******************TO DO*********************
# 1.0 DONE Remove personal details from username/password
# 2.0 DONE change username/password required to true
# 3.0
#
#

import argparse                     # needed for the nice menus and variable checking
import os                           # needed to create directory for user
from datetime import datetime       # needed for the datetime for filename (mostly log)
import requests                     # for all the http/https stuff
from bs4 import BeautifulSoup       # parsing for authtoken
import urllib.parse                 # convert string to url encoded string
import wget                         # used for fast dirty download of images


def load_arguments():

    parser = argparse.ArgumentParser(description='process input')
    parser.add_argument("-u", "--username", required=True, default="nothing",
                        help="username to use to login")
    parser.add_argument("-s", "--secret_password", required=True, default="nothing",
                        help="password used to login to webside")
    parser.add_argument("-f", "--websiteID", required=True, default="username",
                        help="username/ID of the requested scrape")
    parser.add_argument("-v", "--verbose", action='store_true', default=False, help="increase output verbosity", )
    parser.add_argument("-p", "--proxy", required=False, default=False,
                        help="define a proxy for both http and https if required", )
    parser.add_argument("-w", "--website", required=True, default='nothing',
                        help="base url of website e.g bbc.co.uk")
    parser.add_argument("-ACCEPTEULA", "--acceptedeula", action='store_true', default=False,
                        help="Marking this flag accepts EULA embedded withing the script")
    args = parser.parse_args()

    if not args.acceptedeula:
        print("""you need to accept the EULA agreement which is as follows:-
    # EULA
    # This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges 
    # with a varity of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and 
    # arrangements. Until provison of alcohol or baked goodies your on your own but there is no rocket sciecne 
    # involved so dont panic too much. To accept this EULA you must include the correct flag when running the script. 
    # If this script goes crazy wrong and breaks everything then your also on your own and Phil will not accept any 
    # liability of any type or kind. As this script belongs to Phil and NOT Cisco then Cisco cannot be held 
    # responsable for its use or if it goes bad, nor can Cisco make any profit from this script. Phil can profit 
    # from this script but will not assume any liability. Other than the boaring stuff please enjoy and plagerise 
    # as you like (as I have no ways to stop you) but common curtacy says to credit me in some way. 
    # [see above comments on Beer, Wine, Steak and Greggs.].
    
    # To accept the EULA please run with the -ACCEPTEULA flag
        """)
        quit()
    return args


def create_logfile():
    if args.verbose:
        print("creating files and directories")
    try:
        output_filename = datetime.now()
        output_log = open(str(output_filename) + ".text", 'a+')
        output_log.write(str(datetime.now()) + "     " + "log file created sucessfully file name should be " + str(output_filename) + "\n")
    except:
        print ("something went bad opening/creating file for writing")
        quit()

    output_log.write(str(datetime.now()) + "     " + "-v Verbose flag set printing extended ouput" + "\n")
    output_log.write(str(datetime.now()) + "     " + "username to use is " + str(args.username) + "\n")
    output_log.write(str(datetime.now()) + "     " + "password to use is " + str(args.secret_password) + "\n")
    output_log.write(str(datetime.now()) + "     " + "websiteID to use is " + str(args.websiteID) + "\n")
    print("Arguments and files loaded")
    return output_log


def create_directories():
    try:
        output_log.write(str(datetime.now()) + "     " + "trying to create directory" + "\n")
        directory_to_use = os.getcwd() + "/" + args.websiteID
        output_log.write(str(datetime.now()) + "     " + "directory to use will be " + str(directory_to_use) + "\n")
        if not os.path.exists(directory_to_use):
            os.makedirs(directory_to_use, exist_ok=True)
        output_log.write(str(datetime.now()) + "     " + "directory created sucessfully" + "\n")
        os.chdir(directory_to_use)
        output_log.write(str(datetime.now()) + "     " + "changed to new directory" + "\n")
    except:
        output_log.write(str(datetime.now()) + "     " + "something went bad opening/creating file for writing" + "\n")
        quit()
    if args.verbose:
        print("files and directorys created sucessfully")


def check_proxy():
    if args.proxy:
        use_proxies = {
            'http': 'http://' + args.proxy,
            'https': 'http://' + args.proxy,
        }
        output_log.write(str(datetime.now()) + "     " + "proxy flag detected setting proxies" + "\n")
        output_log.write(str(datetime.now()) + "     " + str(use_proxies) + "\n")
    else:
        output_log.write(str(datetime.now()) + "     " + "no proxy settings detected" + "\n")
    if args.verbose:
        print("Checking for internet connection")
    output_log.write(str(datetime.now()) + "     " + "checking for internet connection" + "\n")
    return use_proxies


def connection_check():
    try:
        if not args.proxy:
            connection_check = requests.get("http://www.bbc.co.uk", timeout=15)
        else:
            connection_check = requests.get("http://www.bbc.co.uk", timeout=15, proxies=use_proxies, verify=False)
        # HTTP errors are not raised by default, this statement does that
        connection_check.raise_for_status()
        output_log.write(str(datetime.now()) + "     " + "Internet connection found proceding" + "\n")
    except requests.HTTPError as e:
        print("Checking internet connection failed, status code {0}.".format(e.response.status_code))
        output_log.write(str(datetime.now()) + "     " + "Checking internet connection failed, status code {0}.".format(e.response.status_code) + "\n")
        quit()
    except requests.ConnectionError:
        print("No internet connection available.")
        output_log.write(str(datetime.now()) + "     " + "No internet connection available." + "\n")
        quit()
    except requests.ReadTimeout as e:
        print ("no internet connection avalable read timeout")
        output_log.write(str(datetime.now()) + "     " + "No internet connection avalable read timeout." + "\n")
        quit()


def sign_into_site():
    if args.verbose:
        print ("all internet checks complete starting login")

    output_log.write(str(datetime.now()) + "     " + "all prechecks now complete offical time for kick off is " + str(datetime.now()) + "\n")
    website_session = requests.session()
    output_log.write(str(datetime.now()) + "     " + "Getting login screen datetime is " + str(datetime.now()) + "\n")

    website_http_headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:50.0) '
                                          'Gecko/20100101 Firefox/50.0'}
    try:
        login_inital_url = "https://" + args.website + "/users/sign_in"
        if not args.proxy:
            get_login_screen = website_session.get(login_inital_url, verify=False,
                                                   headers=website_http_headers, timeout=15)
        else:
            get_login_screen = website_session.get(login_inital_url,
                                                   proxies=use_proxies, verify=False, headers=website_http_headers,
                                                   timeout=15)
        output_log.write(str(datetime.now()) + "     " + "Login screen got datetime is " + str(datetime.now()) + "\n")
        output_log.write(str(datetime.now()) + "     " + "response from login was " + str(get_login_screen.status_code) + "\n")
    except:
        print(
            "something bad happened and couldnt fetch login page - There appears to be some connectivity maybe "
            "check for captive portal?")
        output_log.write(str(datetime.now()) + "     " + "something bad happened and couldnt fetch login page - There "
                        "appears to be some connectivity maybe check for captive portal?" + "\n")

    if args.verbose:
        try:
            output_log.write(str(datetime.now()) + "     " + "verbose flag set creating get_login_screen.text" + "\n")
            output_get_login_screen = open("get_login_screen.text", 'w')
            output_log.write(str(datetime.now()) + "     " + "file created sucessfully" + "\n")
            output_get_login_screen.write(get_login_screen.text)
            output_log.write(str(datetime.now()) + "     " + "written get_login_screen.text to get_login_screen.text" + "\n")
            print(str(output_get_login_screen))
            print("login screen text")
        except:
            print("something went bad opening/creating file for writing the login screen output")
            quit()

    if get_login_screen.status_code == 200:
        print("Response from Login splash looking good moving forwards Response was 200 OK")
        output_log.write(str(datetime.now()) + "     " + "Response from Login splash looking good moving forwards Response was 200 OK" + "\n")
    else:
        print("something might not be quite right")
        output_log.write(str(datetime.now()) + "     " + "something might not be quite right" + "\n")
        output_log.write(str(datetime.now()) + "     " + str(get_login_screen.status_code) + "\n")

    output_log.write(str(datetime.now()) + "     " + "processing login screen for auth_token" + "\n")

    soup_parsed_login_response = BeautifulSoup(get_login_screen.text, "html.parser")
    try:
        login_authenticity_token = soup_parsed_login_response.input['value']
    except:
        print("sometimes something goes wrong here with auth token")
        login_authenticity_token = "no auth token"
        output_log.write(str(datetime.now()) + "     " + "sometimes something goes wrong here with auth token" + "\n")
        print(get_login_screen.text)
        quit()


    # This is maybe not needed as the login stage takes a non URL encoded authenticity_token or a URL encoded one
    login_authenticity_token_url_encoded = soup_parsed_login_response.select('input[name="authenticity_token"]')
    if args.verbose:
        output_log.write(str(datetime.now()) + "     " + str(login_authenticity_token_url_encoded) + "\n")
    login_authenticity_token_url_encoded = str(login_authenticity_token_url_encoded[0]).split("value=", 3)[1].split("/>", 1)[0]
    if args.verbose:
        output_log.write(str(datetime.now()) + "     " + "after split" + "\n")
        output_log.write(str(datetime.now()) + "     " + str(login_authenticity_token_url_encoded) + "\n")
        output_log.write(str(datetime.now()) + "     " + "remove quotes" + "\n")
    login_authenticity_token_url_encoded = login_authenticity_token_url_encoded[1:-1]
    if args.verbose:
        output_log.write(str(datetime.now()) + "     " + "before encodeing" + "\n")
    login_authenticity_token_parse_url_encoded = urllib.parse.quote_plus(login_authenticity_token_url_encoded)
    if args.verbose:
        output_log.write(str(datetime.now()) + "     " + "post encoding" + "\n")
        output_log.write(str(datetime.now()) + "     " + str(login_authenticity_token_parse_url_encoded) + "\n")
    if args.verbose:
        output_log.write(str(datetime.now()) + "     " + "printing token non encoded" + "\n")
        output_log.write(str(datetime.now()) + "     " + str(login_authenticity_token) + "\n")
        output_log.write(str(datetime.now()) + "     " + "printed token non encoded" + "\n")

    login_post_url = "https://" + args.website + "/users/sign_in"
    # = login_post_url.split('//', 1)[-1]  # Split right and left to get the defined host from marki cluster
    login_post_payload = "utf8=%E2%9C%93&" + "authenticity_token=" + login_authenticity_token_parse_url_encoded + \
                         "&user%5Botp_attempt%5D=step_1&user%5Blocale%5D=en" + "&user%5Blogin%5D=" + \
                         urllib.parse.quote_plus(args.username) + "&user%5Bpassword%5D=" + \
                         urllib.parse.quote_plus(args.secret_password)

    # Questionable if the headers is needed but it does make the request look more like the browser request.
    login_post_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:50.0) Gecko/20100101 Firefox/50.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://" + args.website + "/users/sign_in",
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }

    if args.verbose:
        output_log.write(str(datetime.now()) + "     " + "printing post headers"+ "\n")
        output_log.write(str(datetime.now()) + "     " + str(login_post_headers) + "\n")
        output_log.write(str(datetime.now()) + "     " + "printing post payload"+ "\n")
        output_log.write(str(datetime.now()) + "     " + str(login_post_payload) + "\n")
    output_log.write(str(datetime.now()) + "     " + "seding details to login dateime was " + str(datetime.now()) + "\n")
    if not args.proxy:
        login_post_send = website_session.post(login_post_url, headers=login_post_headers, data=login_post_payload)
    else:
        login_post_send = website_session.post(login_post_url, headers=login_post_headers, data=login_post_payload,
                                               verify=False, proxies=use_proxies)

    output_log.write(str(datetime.now()) + "     " + "Logged into page dateime was " + str(datetime.now()) + "\n")
    output_log.write(str(datetime.now()) + "     " + "sent post to login prompt POST response was " + str(login_post_send.status_code) + "\n")
    if args.verbose:
        try:
            output_log.write(str(datetime.now()) + "     " + "verbose flag set creating login_post_send.text" + "\n")
            output_login_post_send = open("login_post_send_text.text", 'w')
            output_log.write(str(datetime.now()) + "     " + "file created sucessfully" + "\n")
            output_login_post_send.write(str(login_post_send.text))
            output_log.write(str(datetime.now()) + "     " + "written login_post_send.text to login_post_send.text" + "\n")
            output_log.write(str(datetime.now()) + "     " + "verbose flag set creating login_post_send.text" + "\n")
            output_content_login_post_send = open("login_post_send_content.text", 'w')
            output_log.write(str(datetime.now()) + "     " + "file created sucessfully" + "\n")
            output_content_login_post_send.write(str(login_post_send.content))
            output_log.write(str(datetime.now()) + "     " + "written login_post_send.text to content_login_post_send.text" + "\n")
        except:
            print("something went bad opening/creating login_post_send response for writing")
            quit()

    # this below is nasty implement better method
    try:
        if str(login_post_send.history[0]) == "<Response [302]>":
            print("Response from Login looking good moving forwards Response was 302 Found")
            output_log.write(str(datetime.now()) + "     " + "Response from Login looking good moving forwards Response "
                                                             "was 302 Found" + "\n")
        elif login_post_send.status_code == 200:
            print("Response from Login was bad auth redirected to login page again - 200 OK")
            output_log.write(str(datetime.now()) + "     " + "Response from Login was bad auth redirected to login page "
                                                             "again - 200 OK" + "\n")
            quit()
        else:
            print("something might not be quite right")
            print(login_post_send.status_code)
            print(login_post_send.history)
            output_log.write(str(datetime.now()) + "     " + "something might not be quite right" + "\n")
            output_log.write(str(datetime.now()) + "     " + str(login_post_send.status_code) + "\n")
            output_log.write(str(datetime.now()) + "     " + str(login_post_send.history) + "\n")
    except:
        if login_post_send.status_code == 200:
            print("Response from Login was bad auth redirected to login page again - 200 OK")
            output_log.write(str(datetime.now()) + "     " + "Response from Login was bad auth redirected to login page "
                                                             "again - 200 OK" + "\n")
            quit()
        else:
            print("something might not be quite right")
            print(login_post_send.status_code)
            print(login_post_send.history)
            output_log.write(str(datetime.now()) + "     " + "something might not be quite right" + "\n")
            output_log.write(str(datetime.now()) + "     " + str(login_post_send.status_code) + "\n")
            output_log.write(str(datetime.now()) + "     " + str(login_post_send.history) + "\n")
    return website_session
# above is not nice make something nicer


args = load_arguments()
output_log = create_logfile()
create_directories()
use_proxies = check_proxy()
connection_check()
website_session = sign_into_site()


# Get Picture page 1
# Get picture page count
# recover all IMG SRC
img_get_url = "https://" + args.website + "/users/" + args.websiteID + "/pictures?page=1"

img_get_headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:50.0) Gecko/20100101 Firefox/50.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://" + args.website + "/users/sign_in",
    "Connection": "close",
    "Content-Type": "application/x-www-form-urlencoded",
    "DNT": "1",
    "Upgrade-Insecure-Requests": "1",
}

if not args.proxy:
    page_count_get = website_session.get(img_get_url, headers=img_get_headers)  # data=login_post_payload)
else:
    page_count_get = website_session.get(img_get_url, headers=img_get_headers,  # data=login_post_payload,
                                               verify=False, proxies=use_proxies)
if args.verbose:
    try:
        output_log.write(str(datetime.now()) + "     " + "verbose flag set creating page_count_get_text.text" + "\n")
        page_count_get_text = open("page_count_get_text.text", 'w')
        output_log.write(str(datetime.now()) + "     " + "page_count_get_text file created sucessfully" + "\n")
        page_count_get_text.write(str(page_count_get.text))
        output_log.write(str(datetime.now()) + "     " + "written page_count_get_text.text to page_count_get_text.text" + "\n")
        output_log.write(str(datetime.now()) + "     " + "verbose flag set creating page_count_get_content.text" + "\n")
        page_countent_count_get = open("page_count_get_content.text", 'w')
        output_log.write(str(datetime.now()) + "     " + "page_count_get_content file created sucessfully" + "\n")
        page_countent_count_get.write(str(page_count_get.content))
        output_log.write(str(datetime.now()) + "     " + "written page_count_get_content.text to page_count_get_content.text" + "\n")
    except:
         print("something went bad opening/creating page_count_get_send response for writing")
         quit()

page_count_get_soup = BeautifulSoup(page_count_get.text, "html.parser")

page_count_get_soup_text = page_count_get_soup.find_all("div", "pagination")
page_count_get_soup_soup = BeautifulSoup(str(page_count_get_soup_text), "html.parser")
page_count_links = [0, 1]

for link in page_count_get_soup_soup.find_all('a', href=True):
    print(link['href'])
    print(link['href'].rsplit("="[0])[1])
    page_count_links.append(int(link['href'].rsplit("="[0])[1]))

print("index of largest number")
print(max(page_count_links))
print("array for above index")
print(str(page_count_links))
print("max page number is")
print(int(max(page_count_links)))

img_thumb_links = []

for page_number in range(1, (1 + int(max(page_count_links)))):
    print ("#############################################")
    print(int(max(page_count_links)))
    print("#############################################")
    output_log.write(str(datetime.now()) + "     " + "running loopfor page number " + str(page_number) + "\n")
    img_get_url_pages = "https://" + args.website + "/users/" + args.websiteID + "/pictures?page=" + str(page_number)
    if args.proxy:
        print("**************************")
        print("get page with ID " + str(page_number))
        print("**************************")
        src_count_get = website_session.get(img_get_url_pages, headers=img_get_headers,  # data=login_post_payload,
                                               verify=False, proxies=use_proxies)
    else:
        src_count_get = website_session.get(img_get_url_pages, headers=img_get_headers)  # , data=login_post_payload)
    output_log.write(str(datetime.now()) + "     " + "thumbnail page " + str(page_number) + "collected OK" + "\n")
    src_get_soup = BeautifulSoup(src_count_get.text, "html.parser")
    clearfix_soup_text = src_get_soup.find_all("ul", "page clearfix")
    clearfix_get_soup_soup = BeautifulSoup(str(clearfix_soup_text), "html.parser")
    output_log.write(str(datetime.now()) + "     " + "soup soup is  " + str(clearfix_get_soup_soup) + "\n")
    for link in clearfix_get_soup_soup.find_all('a', href=True):
        print(link['href'])
        img_thumb_links.append(link['href'])
        output_log.write(str(datetime.now()) + "     " + "adding link " + str(link['href']) + " to array" + "\n")

    if args.verbose:
        try:
            output_log.write(str(datetime.now()) + "     " + "verbose flag set creating picture_url_get_text_page_" +
                             str(page_number) + ".text" + "\n")
            page_count_get_text = open("picture_url_get_text_page_" + str(page_number) + ".text", 'w')
            output_log.write(str(datetime.now()) + "     " + "picture_url_get_text_page_" + str(page_number) +
                             " file created sucessfully" + "\n")
            page_count_get_text.write(str(src_count_get.text))
            output_log.write(str(datetime.now()) + "     " + "written picture_url_get_text_page_" + str(page_number) +
                             ".text to picture_url_get_text.text" + "\n")
            output_log.write(str(datetime.now()) + "     " + "verbose flag set creating picture_url_get_content_page_"
                             + str(page_number) + ".text" + "\n")
            page_countent_count_get = open("picture_url_get_content_page_" + str(page_number) + ".text", 'w')
            output_log.write(str(datetime.now()) + "     " + "picture_url_get_content_page_" + str(page_number) +
                             " file created sucessfully" + "\n")
            page_countent_count_get.write(str(src_count_get.content))
            output_log.write(str(datetime.now()) + "     " + "written picture_url_get_content_page_" + str(page_number)
                             + ".text to picture_url_get_content_page_" + str(page_number) + ".text" + "\n")
            page_count_get_text.close()
            page_countent_count_get.close()
        except:
             print("something went bad opening/creating picture_url_get_content response for writing")
             quit()

print("this is what pages should be grabbed start")
print(str(img_thumb_links))
print("this is what pages should be grabbed end")
img_big_links = []

for picture_number in range(0, len(img_thumb_links)):
    img_get_img_pages = img_thumb_links[picture_number]
    print("retreaving site " + str(img_get_img_pages))
    if args.proxy:
        img_id_get = website_session.get(img_get_img_pages, headers=img_get_headers,  # data=login_post_payload,
                                               verify=False, proxies=use_proxies)
    else:
        img_id_get = website_session.get(img_get_img_pages, headers=img_get_headers)  # , data=login_post_payload)
    img_src_soup = BeautifulSoup(img_id_get.text, "html.parser")
    img_src_soup_text = img_src_soup.find_all("div", "picture_container")
    img_src_soup_soup = BeautifulSoup(str(img_src_soup_text), "html.parser")
    print("adding the following URL to request list")

    print(str(img_src_soup_soup.find('img')['src']))
    img_big_links.append(str(img_src_soup_soup.find('img')['src']))
    output_log.write(str(datetime.now()) + "     " + "written URL to get list" +
                     str(img_src_soup_soup.find('img')['src']) + "\n")
    print("URL sucessfully added to request list")

    if args.verbose:
        try:
            output_log.write(str(datetime.now()) + "     " + "verbose flag set creating picture_big_url_get_text_page_"
                             + str(picture_number) + ".text" + "\n")
            img_id_get_text = open("picture_big_url_get_text_page_" + str(picture_number) + ".text", 'w')
            output_log.write(str(datetime.now()) + "     " + "picture_big_url_get_text_page_" + str(picture_number) +
                             " file created sucessfully" + "\n")
            img_id_get_text.write(str(img_id_get.text))
            output_log.write(str(datetime.now()) + "     " + "written picture_big_url_get_text_page_" +
                             str(picture_number) + ".text to picture_big_url_get_text_page_.text" + "\n")
            output_log.write(str(datetime.now()) + "     " + "verbose set creating picture_big_url_get_content_page_"
                             + str(picture_number) + ".text" + "\n")
            img_id_get_content = open("picture_big_url_get_content_page_" + str(picture_number) + ".text", 'w')
            output_log.write(str(datetime.now()) + "     " + "picture_big_url_get_content_page_" + str(picture_number) +
                             " file created sucessfully" + "\n")
            img_id_get_content.write(str(img_id_get.content))
            output_log.write(str(datetime.now()) + "     " + "written picture_big_url_get_content_page_" + str(picture_number)
                             + ".text to picture_big_url_get_content_page_" + str(picture_number) + ".text" + "\n")
            img_id_get_text.close()
            img_id_get_content.close()
        except:
            print("something went bad opening/creating picture_big_url_get_content_page_ response for writing")
            quit()
    img_get_img_url = str(img_src_soup_soup.find('img')['src'])

    name_working_0 = str(img_get_img_url.split("?", 1)[0])
    print(name_working_0)
    image_filename = str(name_working_0.split("/")[-1])
    print(image_filename)

    if not args.proxy:
        img_get = website_session.get(img_get_img_url, headers=img_get_headers)  # , data=login_post_payload)
        wget.download(img_get_img_url, out=image_filename, )
    else:
        img_get = website_session.get(img_get_img_url, headers=img_get_headers,  # data=login_post_payload,
                            verify=False, proxies=use_proxies)
        wget.download(img_get_img_url, out=image_filename, )
print("all links")
print(str(img_big_links))

output_log.close()
quit()
