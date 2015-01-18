import argparse
import urllib2, socket,sys,base64,os
from xml.dom.minidom import parse, parseString
import socket
from urlparse import urlparse
import time
import multiprocessing
import random

bingAPIKeyList = []
bingAPIKeyList.append('')

num_processes=2

def getIP(domain):
    found=False
    while found==False:
	try:
	    	result = socket.gethostbyname(domain)
		return result
		found = True
	except:
		print "Sleeping for 5 seconds"
		time.sleep(5)
		continue
   
def reverseBing(ip): 
    sites = []
    skip = 0
    top = 50
    found=False
   
    while skip < 200:
	  found=False
	  while found==False:
	  	try:
          		url = "https://api.datamarket.azure.com/Data.ashx/Bing/Search/v1/Web?Query='ip:%s'&$top=%s&$skip=%s&$format=Atom"%(ip,top,skip)
          		request = urllib2.Request(url)
			bingAPIKey = (random.choice(bingAPIKeyList))
          		auth = base64.encodestring("%s:%s" % (bingAPIKey, bingAPIKey)).replace("\n", "")
          		request.add_header("Authorization", "Basic %s" % auth)
          		res = urllib2.urlopen(request)
          		data = res.read()
			found=True
		except:
			continue

          xmldoc = parseString(data)
          site_list = xmldoc.getElementsByTagName('d:Url')
          for site in site_list:
              domain = site.childNodes[0].nodeValue
              domain = domain.split("/")[2]
	      tmpDomain = domain
	      if ":" in domain:
		 domain = domain.split(":")[0]
              if tmpDomain not in sites:
		 siteIP = getIP(domain)
	   	 #if ip not in sites:
	 	 # 	 sites.append(ip)
		 if ip==siteIP:
	       	         sites.append([ip,tmpDomain])
          skip += 50
    return sites	

class Worker(multiprocessing.Process):

    def __init__(self,
            work_queue,
            result_queue,
          ):
        # base class initialization
        multiprocessing.Process.__init__(self)
        self.work_queue = work_queue
        self.result_queue = result_queue
        self.kill_received = False

    def run(self):
        while (not (self.kill_received)) and (self.work_queue.empty()==False):
            try:
                job = self.work_queue.get_nowait()
            except:
                break

            (jobid,method,hostIP) = job
	    if method=="reverseBing":
	            rtnVal = (jobid,reverseBing(hostIP))
        	    self.result_queue.put(rtnVal)

def execute(jobs, num_processes=2):
    # load up work queue
    work_queue = multiprocessing.Queue()
    for job in jobs:
        work_queue.put(job)

    # create a queue to pass to workers to store the results
    result_queue = multiprocessing.Queue()

    # spawn workers
    worker = []
    for i in range(int(num_processes)):
        worker.append(Worker(work_queue, result_queue))
        worker[i].start()

    # collect the results from the queue
    results = []
    while len(results) < len(jobs): #Beware - if a job hangs, then the whole program will hang
        result = result_queue.get()
        results.append(result)
    results.sort() # The tuples in result are sorted according to the first element - the jobid
    return (results)


parser = argparse.ArgumentParser(description='Bing Reverse IP Lookup')
parser.add_argument('-ip', help='Enter an IP address')
parser.add_argument('-file', help='Enter a filename containing list of IP addresses')
parser.add_argument('-n', dest='numProcesses',  action='store', help='[number of threads]')
options = parser.parse_args()

if options.ip==None and options.file==None:
	sys.exit()
else:
	if options.ip:
		sites = reverseBing(options.ip)
		tempList=[]
		for site in sites:
			hostName = site[1]
			if hostName not in tempList and hostName!=options.ip:
				tempList.append(hostName)
		for x in tempList:
			print x
		sys.exit()
	if options.file:
		if options.numProcesses:
			numProcesses=options.numProcesses
		jobs=[]
		jobid = 0
		lines=[]
		with open(options.file) as f:
       			lines = f.readlines()
		for line in lines:
			line = line.strip()
			jobs.append((jobid,"reverseBing",line))
			jobid = jobid+1
		results = execute(jobs,int(numProcesses))
		for result in results:
			if result[1]!=None:
				for x in result[1]:
					print x[0]+"\t"+x[1]
