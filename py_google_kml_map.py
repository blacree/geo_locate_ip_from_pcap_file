"""This python script takes ip-address and lat and long coordinates to build a graphical KML map
that makes use of xml structure"""

from os import link
import geoip2.database		
import dpkt
import socket
import optparse

reader = geoip2.database.Reader('GeoLite2-City_20200707/GeoLite2-City.mmdb')

def kml_linemap(source_ip, dest_ip):
	try:
		source_maping = reader.city(source_ip)
		latitude_source = source_maping.location.latitude
		longitude_source = source_maping.location.longitude

		dest_maping = reader.city(dest_ip)
		latitude_destination = dest_maping.location.latitude
		longitude_destination = dest_maping.location.longitude
		kml = ('<Placemark>\n'
		'<LineString>\n'
		'<coordinates>%6f,%6f,0.0 %6f,%6f,0.0 </coordinates>\n'
		'</LineString>\n'
		'<Style> \n'
		'<LineStyle>\n'
		'<color>#ff0000ff</color>\n'
		'</LineStyle> \n'
		'</Style>\n'
		'</Placemark>\n'
		%(longitude_source, latitude_source, longitude_destination,latitude_destination))

		return kml
	except:
		return ''



def kmlmap_source(ip, dst):
	try:
		maping = reader.city(ip)
		latitude = maping.location.latitude
		longitude = maping.location.longitude
		kml = ('<Placemark>\n'
			'<name>%s - SOURCE(Dest:%s)</name>\n'
			'<Point>\n'
			'<coordinates>%6f,%6f</coordinates>\n'
			'</Point>\n'
			'</Placemark>\n'
			%(ip, dst, longitude, latitude))
		return kml
	except Exception as e:
		return ''

def kmlmap_destination(ip, src):
	try:
		maping = reader.city(ip)
		latitude = maping.location.latitude
		longitude = maping.location.longitude
		kml = ('<Placemark>\n'
			'<name>%s - DESTINATION(Source:%s))</name>\n'
			'<Point>\n'
			'<coordinates>%6f,%6f</coordinates>\n'
			'</Point>\n'
			'</Placemark>\n'
			%(ip, src, longitude, latitude))
		return kml
	except Exception as e:
		return ''


def plotIps(pcap):
	source_ips = []
	destination_ips = []
	identified_links = []
	drawn_links = []
	not_in_database = []
	links_not_drawn = []
	kmlPts = ''
	check_source = True
	check_destination = True
	linked_counter = 0
	for (ts, buf) in pcap:
		# try:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		try:
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			linked = src+'-'+dst
		except:
			continue

		if ('192.168' in src) or ('192.168' in dst):
			continue
		
		if linked not in drawn_links:
			if src not in source_ips:
				srckml = kmlmap_source(src, dst)
				source_ips.append(src)
				if srckml:
					check_source = True
				else:
					check_source = False
					not_in_database.append(src+'-source')

			if dst not in destination_ips:
				dstkml = kmlmap_destination(dst, src)
				destination_ips.append(dst)
				if dstkml:
					check_destination = True
				else:
					check_destination = False
					not_in_database.append(dst+'-destination')

			line_kml = kml_linemap(src, dst)
			identified_links.append(linked)
			
			if line_kml:
				if check_destination and check_source:
					kmlPts += srckml + dstkml + line_kml
					linked_counter += 1
				elif (check_source == True) and (check_destination == False):
					kmlPts += srckml + line_kml
					linked_counter += 1
				else:
					if (check_destination == True) and (check_source == False):
						kmlPts += dstkml + line_kml
						linked_counter += 1
				drawn_links.append(linked)
			else:
				links_not_drawn.append(linked)
		else:
			pass

	print('The following addresses are not in the database: NOT_IN_DATABASE')
	print(not_in_database)
	print()
	print('[+] No of identified links: '+ str(len(identified_links)))
	print('[+] No of drawn links: '+ str(linked_counter))
	print('\n[+] The drawnlinks are: ')
	print(drawn_links)
	print('\n[-] Links not drawn are: ')
	print(links_not_drawn)
	return kmlPts
			

# main function()
def main():
	# collect the required options passed to script
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
	# set the structure of the KML document
	kmldoc = kmlheader+plotIps(pcap)+kmlfooter
	# print(kmldoc)
	print()
	# save  the generated kml structure
	document = open('traffic_map.kml', 'w')
	document.write(kmldoc)
	document.close
	print('[*]Your kml document has being created: "traffic_map.kml".')
	

# start main function()
if __name__ == '__main__':
	main()
	
	
	

