# Created by Blake Cornell, CTO, Integris Security LLC
# Integris Security Carbonator - Beta Version - v0.1
# Released under GPL Version 2 license.
#
# See the INSTALL file for installation instructions.
# 
# For more information contact us at carbonator at integrissecurity dot com
# Or visit us at https://www.integrissecurity.com/
from burp import IBurpExtender
from burp import IHttpListener
from urlparse import urlparse
from burp import IScannerListener
from java.net import URL
from java.io import File
import socket
import time
import os

filename = ""
txtReport = []
saveState = False

def isOpen(ip,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
     s.connect((ip, int(port)))
     s.shutdown(2)
     return True
    except:
     return False

def constructURL(urlLink):
	parse_object = urlparse(urlLink)
	scheme1 = str(parse_object.scheme)
	fqdn1 = str(parse_object.hostname)
	#self.hostname = str(parse_object.hostname)
	path1 = parse_object.path
	port1 = parse_object.port
	if not port1:	
		if scheme1=='http': 
			port1 = int(80)
		elif scheme1=='https':
			port1 = int(443)
	url1 = URL(scheme1,fqdn1,port1,path1)
	return url1

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):
    def registerExtenderCallbacks(self, callbacks):
	self._callbacks = callbacks
	self._callbacks.setExtensionName("Integris Security Carbonator")
	self._helpers = self._callbacks.getHelpers()
	self.clivars = None

	self.spider_results=[]
	self.scanner_results=[]
	self.packet_timeout=5

	self.last_packet_seen= int(time.time()) #initialize the start of the spider/scan

	if not self.processCLI():
		return None
	else:
		self.clivars = True

        if os.path.exists('links.txt'):
		try:
			with open('links.txt') as f:
				for line in f:
					url = constructURL(line)
					print line
					self._callbacks.includeInScope(url)
					self._callbacks.sendToSpider(url)
					self._callbacks.registerHttpListener(self)
					self._callbacks.registerScannerListener(self)
       	 	except IOError:
                	pass

	#add to scope if not already in there.
	if self._callbacks.isInScope(self.url) == 0:
		self._callbacks.includeInScope(self.url)

	self._callbacks.sendToSpider(self.url)
	self._callbacks.registerHttpListener(self)
	self._callbacks.registerScannerListener(self)

	while int(time.time())-self.last_packet_seen <= self.packet_timeout:
		time.sleep(1)
	print "No packets seen in the last ", self.packet_timeout, " seconds."
	print "Removing Listeners"
	self._callbacks.removeHttpListener(self)
	self._callbacks.removeScannerListener(self)

	if saveState==True:
		self._callbacks.saveState(File(filename))	
	else:
		print "No high/medium risk issues found."

	self._callbacks.excludeFromScope(self.url)


	print "Generating Report"
	self.generateReport('HTML')
	print "Report Generated"
	print "Closing Burp in ", self.packet_timeout, " seconds."
	time.sleep(self.packet_timeout)

	#f = open("burp_result.txt", "w")
	#f.write("\n".join(map(lambda x: str(x), txtReport)) + "\n")
	#f.close()

	if self.clivars:
		self._callbacks.exitSuite(False)
		
	return

    def processHttpMessage(self, tool_flag, isRequest, current):
	self.last_packet_seen = int(time.time())
	if tool_flag == self._callbacks.TOOL_SPIDER and isRequest: #if is a spider request then send to scanner
		self.spider_results.append(current)
		print "Sending new URL to Vulnerability Scanner: URL #",len(self.spider_results)
		if self.scheme == 'https':
			self._callbacks.doActiveScan(self.fqdn,self.port,1,current.getRequest()) #returns scan queue, push to array
		else:
			self._callbacks.doActiveScan(self.fqdn,self.port,0,current.getRequest()) #returns scan queue, push to array
	return

    def newScanIssue(self, issue):
	self.scanner_results.append(issue)
	print "New issue identified: Issue #",len(self.scanner_results);
	if issue.getSeverity()=="High":
		global saveState
		saveState=True
	#global txtReport
	#tmpText = str(issue.getSeverity())+"\n"+str(issue.getIssueName())+"\n"+str(issue.getIssueDetail())+"\n"+str(issue.getIssueBackground())+"\n"
	#txtReport.append(tmpText)
	
	#print str(issue.getHttpMessages())
	#print issue.getHttpMessages()
	#print (issue.getHttpMessages().getRequest()

	#print issue.getSeverity()
	#print issue.getIssueName()
	#print issue.getIssueType()
	#print issue.getIssueBackground()
	#print issue.getIssueDetail()
	return

    def generateReport(self, format):
	if format != 'XML':
		format = 'HTML'	
	#f = File.open('IntegrisSecurity_Carbonator_'+self.scheme+'_'+self.fqdn+'_'+str(self.port)+'.txt'))
	#for i in textReport
	#	f.write(i)

	self._callbacks.generateScanReport(format,self.scanner_results,File('IntegrisSecurity_Carbonator_'+self.scheme+'_'+self.fqdn+'_'+str(self.port)+'.'+format.lower()))
	return


    def processCLI(self):
        cli = self._callbacks.getCommandLineArguments()
        if len(cli) > 0:
                #print "Incomplete target information provided."
		try:
			if cli[1]:
				saveText = cli[1].lower()
				if saveText=='save':
					global saveState
					saveState=True
		except IndexError:
			global saveState
			saveState=False
		urlLink = cli[0]
		
		if 'http' not in urlLink and 'https' not in urlLink:
			if isOpen(urlLink,80):
				urlLink = 'http://'+urlLink			
			elif isOpen(urlLink,443):
				urlLink = 'https://'+urlLink			
			
		parse_object = urlparse(urlLink)
		self.scheme = str(parse_object.scheme)
		#self.fqdn = str(parse_object.netloc)
		self.fqdn = str(parse_object.hostname)
		#self.hostname = str(parse_object.hostname)

		self.path = parse_object.path
		#self.port = parse_object.port
		if self.scheme=='http': 
			self.port = int(80)
		elif self.scheme=='https':
			self.port = int(443)
                self.url = URL(self.scheme,self.fqdn,self.port,self.path)
		global filename
		filename = "burpstate_"+self.scheme+"_"+self.fqdn+"_"+str(self.port)+".html"
                return True
        elif cli[0] == 'https' or cli[0] == 'http': 
		self.scheme = cli[0]
                self.fqdn = cli[1]
                self.port = int(cli[2])
                if len(cli) == 3:
                        self.path = '/'
                elif len(cli) == 4:
                        self.path = cli[3]
                else:
                        print "Unknown number of CLI arguments"
                        return False
                self.url = URL(self.scheme,self.fqdn,self.port,self.path)
		global filename
		filename = "burpstate_"+self.scheme+"_"+self.fqdn+"_"+str(self.port)+".html"
        else:
                print "Invalid command line arguments supplied"
                return False
        return True
