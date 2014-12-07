import glob
import os
import commands
origPath=os.getcwd()
def RunCommand(fullCmd):
    	try:
        	return commands.getoutput(fullCmd)
	except:
        	return "Error executing command %s" %(fullCmd)

for filename in glob.glob(origPath+"/IntegrisSecurity_Carbonator_*"):
	#print filename
	cmd = "html2text "+filename
	#print cmd
	results = RunCommand(cmd)
	resultList = results.split("\n")
	markerStart = False
	emptyLineCount = 0
	matchOnce = 0
	contents=[]
	for x in resultList:
		#if emptyLineCount==3:
		#	marketStart=False
		if len(x.strip())==0:
			if emptyLineCount<3:
				emptyLineCount+=1
			if emptyLineCount==3:
				marketStart=False
		else:
			if markerStart==True:
				if x.strip().startswith("1. "):
					matchOnce+=1
				if matchOnce==1:
					contents.append(x)
		if x.strip()=="# Contents":
			markerStart=True
	if len(contents)>0:
		print "\n"+filename
		for content in contents:
			print content
