import httplib
import xml.etree.ElementTree
import hmac
import md5
import time
import sys

ip = ''
pin = ''
power = ''

if len(sys.argv) < 4:
	print 'Usage: ' + sys.argv[0] + ' <ip> <pin> <on/off>'
	exit(1)

ip = sys.argv[1]
pin = sys.argv[2]


if sys.argv[3] == 'on':
	power = 'true'
elif sys.argv[3] == 'off':
	power = 'false'
else:
	print 'Usage: ' + sys.argv[0] + ' <ip> <pin> <on/off>'
	exit(1)

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
the_page = response.read()
xmldata = xml.etree.ElementTree.fromstring(the_page)

for a in xmldata.findall('{http://schemas.xmlsoap.org/soap/envelope/}Body'):
     for b in a.findall('{http://purenetworks.com/HNAP1/}LoginResponse'):
	challenge = b.findtext('{http://purenetworks.com/HNAP1/}Challenge')
	cookie = b.findtext('{http://purenetworks.com/HNAP1/}Cookie')
	publickey = b.findtext('{http://purenetworks.com/HNAP1/}PublicKey')
	loginresult = b.findtext('{http://purenetworks.com/HNAP1/}LoginResult')

print 'GET AUTH: ' + loginresult

encdata = hmac.new(publickey + pin , challenge, md5)
privatekey = encdata.hexdigest().upper()
encdata = hmac.new(privatekey, challenge, md5)
loginpassword = encdata.hexdigest().upper()

data = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>login</Action><Username>Admin</Username><LoginPassword>' + loginpassword + '</LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>'


headers = {
    'Content-Type': 'text/xml; charset=utf-8',
    'SOAPAction' : '"http://purenetworks.com/HNAP1/Login"',
    'Content-Length' : "%d"%(len(data)),
    'Cookie' : 'uid=' + cookie
    }

request = conn.putrequest('POST', '/HNAP1/')
for i in headers:
    conn.putheader(i, headers[i])
conn.endheaders()
conn.send(data)
response = conn.getresponse()
the_page = response.read()
xmldata = xml.etree.ElementTree.fromstring(the_page)
for a in xmldata.findall('{http://schemas.xmlsoap.org/soap/envelope/}Body'):
     for b in a.findall('{http://purenetworks.com/HNAP1/}LoginResponse'):
	loginresult = b.findtext('{http://purenetworks.com/HNAP1/}LoginResult')

print "LOGIN: " + loginresult

timestamp = str(int(time.time()))

encdata = hmac.new(privatekey,timestamp + '"http://purenetworks.com/HNAP1/SetSocketSettings"',md5)
hnapauth = encdata.hexdigest().upper() + ' ' + timestamp


data = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetSocketSettings xmlns="http://purenetworks.com/HNAP1/"><ModuleID>1</ModuleID><NickName>Socket 1</NickName><Description>Socket 1</Description><OPStatus>' + power + '</OPStatus><Controller>1</Controller></SetSocketSettings></soap:Body></soap:Envelope>'


headers = {
    'Content-Type': 'text/xml; charset=utf-8',
    'SOAPAction' : '"http://purenetworks.com/HNAP1/SetSocketSettings"',
    'HNAP_AUTH'  :  hnapauth,
    'Content-Length' : "%d"%(len(data)),
    'Cookie' : 'uid=' + cookie
    }

request = conn.putrequest('POST', '/HNAP1/')
for i in headers:
    conn.putheader(i, headers[i])
conn.endheaders()
conn.send(data)
response = conn.getresponse()
the_page = response.read()
xmldata = xml.etree.ElementTree.fromstring(the_page)
for a in xmldata.findall('{http://schemas.xmlsoap.org/soap/envelope/}Body'):
     for b in a.findall('{http://purenetworks.com/HNAP1/}SetSocketSettingsResponse'):
	socketresult = b.findtext('{http://purenetworks.com/HNAP1/}SetSocketSettingsResult')

print "SEND COMMAND: " + socketresult


conn.close()


