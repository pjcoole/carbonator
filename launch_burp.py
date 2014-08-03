import argparse
import urllib2, socket,sys,base64,os
from xml.dom.minidom import parse, parseString
import socket
from google import search

#http://winappdbg.sourceforge.net/blog/google-1.06.tar.gz
bingAPIKey = ''
burpPath = '/pentest/burp/burpsuite_pro_v1.6beta.jar'
runHeadless = False

def removeFile():
	try:
		os.remove('links.txt')
	except OSError:
		pass

def getIP(domain):
    return socket.gethostbyname(domain)

def getGoogleResults(domain):
    urls = []
    for url in search('site:'+domain, stop=50):
       urls.append(url)
    f = open('links.txt', 'w')
    for item in urls:
  	f.write("%s\n" % item)
    f.close()
    return urls

def reverseBing(ip):
    sites = []
    skip = 0
    top = 50

    while skip < 200:
          url = "https://api.datamarket.azure.com/Data.ashx/Bing/Search/v1/Web?Query='ip:%s'&$top=%s&$skip=%s&$format=Atom"%(ip,top,skip)
          request = urllib2.Request(url)
          auth = base64.encodestring("%s:%s" % (bingAPIKey, bingAPIKey)).replace("\n", "")
          request.add_header("Authorization", "Basic %s" % auth)
          res = urllib2.urlopen(request)
          data = res.read()

          xmldoc = parseString(data)
          site_list = xmldoc.getElementsByTagName('d:Url')
          for site in site_list:
              domain = site.childNodes[0].nodeValue
              domain = domain.split("/")[2]
              if domain not in sites:
                 sites.append(domain)

          skip += 50

    print "Total domains found: %s \n" %(len(sites))
    for site in sites:
        print site
    return sites	

def runBurp(url):
	if runHeadless==True:
		cmd = 'java -jar -Xmx1024m -Djava.awt.headless=true '+burpPath+' '+url
	else:	
		cmd = 'java -jar -Xmx1024m '+burpPath+' '+url
	print cmd
	os.system(cmd)

parser = argparse.ArgumentParser(description='Burp automator')
parser.add_argument('-host', help='Enter an IP address or Domain name')
parser.add_argument('-saveState', action='store_true', help='Save Burpsuite State')
parser.add_argument('-enableBing', action='store_true', help='Enable Bing Reverse IP')
parser.add_argument('-enableGoogle', action='store_true', help='Enable Google Search')
parser.add_argument('-headless', action='store_true', help='Run Burp headless')
args = parser.parse_args()
print args.host

if args.headless:
	global runHeadless
	runHeadless=True

if any(c.isalpha() for c in args.host)==False:
	if args.enableBing==True:
		if len(bingAPIKey)<1:
			sys.exit("[!] Please check your bingAPIKey !")
		sites = reverseBing(args.host)
		for site in sites:
			if args.saveState:
				site+=' save'
			if args.enableGoogle:
				getGoogleResults(site)
			else:
				removeFile()
			runBurp(site)
	else:
		site = args.host
		if args.saveState:
			site+=' save'
		if args.enableGoogle:
			getGoogleResults(site)
		else:
			removeFile()

		runBurp(site)

else:
	if args.enableBing==True:
		ip = getIP(args.host)
		sites = reverseBing(ip)
		for site in sites:
			ipSite = getIP(site)
			if ip==ipSite:
				if args.saveState:
					site+=' save'
				if args.enableGoogle:
					getGoogleResults(site)
				else:
					removeFile()
				runBurp(site)
	else:
		site = args.host
		if args.saveState:
			site+=' save'
		if args.enableGoogle:
			getGoogleResults(site)
		else:
			removeFile()
		runBurp(site)


