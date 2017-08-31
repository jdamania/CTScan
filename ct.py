import requests
import os.path
import json
import sys

def printReport(number,title,message):
        print '\n'
        print '######################################################################'
        print number,'.',title
        print '######################################################################'
        print message

def refineData(jsonKey):
	tempArray = {}

        for i in ct_data:
                if i[jsonKey] not in tempArray:
                        tempArray[i[jsonKey]] = 1
                else:
                        tempArray[i[jsonKey]] += 1

        tempStr = ''

        for key,value in tempArray.iteritems():
                tempStr += str(key)+" -> "+str(value)+"\n"
	
	return tempStr

def newLine(listVal):
	listStr = ''
	
	for i in set(listVal):
		listStr += i+"\n"
	
	return listStr
	
def uniqueDomains():
	san = []
	domainName = domain.split('.')
	
	for i in ct_data:
		for j in i["san"]:
			if j["valueReversed"][::-1] not in san and domainName[0] in j["valueReversed"][::-1]:
				san.append(j["valueReversed"][::-1])
	
	message = newLine(san)
	
	printReport(7,'List of unique domain names found',message)

def commonName():
	cn = []
	ou = []

	for i in ct_data:
		tempVar = i["subjectDN"].split(',')
		tempVarCN = tempVar[0].split('=')
		
		if domain  not in tempVarCN[1]:
			cn.append(tempVarCN[1])	
		
		if len(tempVar) > 1:
			tempVarOU = tempVar[1].split('=')		
			if tempVarOU[1].upper() not in ou and domain in tempVarCN[1]:
				ou.append(tempVarOU[1].upper())
	
	cnStr = newLine(cn)	
	ouStr = newLine(ou)		
	
	messageCN = "Certificates were found where "+domain+" domain is in Subject Alternative Name (SAN) but the CN is a different domain \n"+cnStr
	printReport(5,'Common Name (cn) without '+domain ,messageCN)

	printReport(6,'Organizational Units which  created the certificates',ouStr)
	
def certificateAuthority():
        message = refineData("issuerO")
        printReport(4, 'Number of certificates issued by each CA',message)

def signAlg():	
	message = refineData("signAlg")
	printReport(3,'Signature Algorithm used in certificates',message)

def keySizeAndType():
	keyTypeStr = refineData("publicKeyType") 
	keySizeStr = refineData("publicKeySize")	

	message = "Public keyType analysis (keyType -> number of certificates using keyType) \n"+keyTypeStr
	message += "Public keySize analysis (keySize -> number of certificates using keySize) \n"+keySizeStr
	
	printReport(2,'Key Type and Size', message)

def totalCerts():
	counter = 0
        
	for i in ct_data:
        	counter += 1
	
	message = str(counter) + " certificates were found with common name as "+domain+" (including subdomain)"         
        printReport(1,'Total Certificates',message)	

def callApi():
	global ct_data
	global domain

	domain = sys.argv[1]
	fileName = domain.split('.')
	fileName = fileName[0]+".json"

	if not os.path.isfile(fileName):
		url = "https://ctsearch.entrust.com/api/v1/certificates?fields=issuerCN,subjectO,issuerDN,issuerO,subjectDN,signAlg,san,publicKeyType,publicKeySize,validFrom,validTo,sn,ev,logEntries.logName,subjectCNReversed,cert&domain="+domain+"&includeExpired=false&exactMatch=false&limit=5000"
    		response = requests.get(url,proxies={"https":"http://www-proxy.us.oracle.com:80"})
		with open(fileName, 'w') as f:
    			f.write(response.content)

	with open(fileName) as f:   
    		ct_data = json.load(f)

	totalCerts()
	keySizeAndType()
	signAlg()	
	certificateAuthority()
	commonName()
	uniqueDomains()

callApi()
