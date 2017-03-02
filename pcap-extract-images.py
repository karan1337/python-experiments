#reference: http://bt3gl.github.io/black-hat-python-infinite-possibilities-with-the-scapy-module.html

from scapy.all import *

#def packet_callback(packet):
#	print packet.show()

#p = sniff(filter='icmp', iface='en1', prn=packet_callback, count=1)
#print p.summary()

#a = Ether()/IP(dst="www.yahoo.com")/TCP()/"GET /index.html HTTP/1.1"
#hexdump(a)

def writeimagetofile(image, image_type, carved_number):
	
	dirpath = "carved"
	if not os.path.exists(dirpath):
		os.makedirs(dirpath)	
	filename = 'pic_carver_%d.%s' % (carved_number, image_type)
	fd = open(dirpath+"/"+filename, 'wb')
	fd.write(image)
	fd.close()		

def extract_image(headers, tcp_payload):

	try:
		image_type = headers['Content-Type'].split("/")[1]
		image = tcp_payload[tcp_payload.index("\r\n\r\n")+4:]	
		try:
			if "Content-Encoding" in headers.keys():
				if headers['Content-Encoding'] == 'gzip':
					image = zlib.decompress(image, 16+zlib.MAX_WBITS)
				elif headers['Content-Encoding'] == "deflate":
					image = zlib.decompress(image)
		except:
			pass
	except:
		return None, None
	return image, image_type
	
	
def get_http_headers(http_payload):
	try:
		headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
		headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
	except:
		return None
	if 'Content-Type' not in headers:
		return None
	return headers	


p = rdpcap('test.pcap')
sessions = p.sessions()

counter=0
for session in sessions:
	#sessions print layer 4 information (protocol, src/dst IP/port)
	#print str(session)
	tcp_payload = ''
	for packet in sessions[session]:
		#print hexdump of entire packet (all layers)
		#print str(packet)
		try:
			if packet[TCP].dport == 80 or packet[TCP].sport == 80:
				tcp_payload += str(packet[TCP].payload)
				#print str(packet[TCP])
		except:
			pass
		
	headers = get_http_headers(tcp_payload)
	if headers is None:
		continue
	elif "image" in headers['Content-Type']:
		image, image_type = extract_image(headers, tcp_payload)
		writeimagetofile(image, image_type, counter)
		counter = counter + 1 
		#print str(image_type)
		#print "Header=" + str(headers)
				
