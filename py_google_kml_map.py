"""This python script takes ip-address and lat and long coordinates to build a graphical KML map
that makes use of xml structure"""

import geoip2.database		
import dpkt
import socket
import optparse

reader = geoip2.database.Reader('GeoLite2-City_20200707/GeoLite2-City.mmdb')

def kmlmap(ip):
	try:
		maping = reader.city(ip)
		latitude = maping.location.latitude
		longitude = maping.location.longitude
		kml = ('<Placemark>\n'
			'<name>%s</name>\n'
			'<Point>\n'
			'<coordinates>%6f,%6f</coordinates>\n'
			'</Point>\n'
			'</Placemark>\n'
			%(ip, longitude, latitude))
		return kml
	except Exception as e:
		return ''


def plotIps(pcap):
	kmlPts = ''
	for (ts, buf) in pcap:
		try:
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			#print('[+]Src: ' + src + ' Dest: ' + dst)
			if '192.168' in src:
				continue
			else:
				srckml = kmlmap(src)
				dstkml = kmlmap(dst)
				kmlPts = kmlPts + srckml + dstkml
		except:
			pass
	return kmlPts
			
			
def main():
	parser = optparse.OptionParser('[*]Run: python3 script.py -f <pcap_file>')
	parser.add_option('-f', dest='pcap_file', type='string', help='input the correct file')
	(options, args) = parser.parse_args()
	if (options.pcap_file == None):
		print(parser.usage)
		exit()
	else:
		pcap_file = options.pcap_file
	f = open(pcap_file, 'rb')
	pcap = dpkt.pcap.Reader(f)
	kmlheader = '<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'
	kmlfooter = '</Document>\n</kml>\n'
	kmldoc = kmlheader+plotIps(pcap)+kmlfooter
	print(kmldoc)
	print()
	document = open('traffic_map.kml', 'w')
	document.write(kmldoc)
	document.close
	print('[*]Your kml document has being created: "trafficmap.kml".')
	
if __name__ == '__main__':
	main()
	
	
	

