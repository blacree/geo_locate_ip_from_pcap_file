import dpkt
import socket
import geoip2.database

reader = geoip2.database.Reader('/root/Downloads/geolite_database/GeoLite2-City_20200707/GeoLite2-City.mmdb')

def printPcap(pcap):
	for (ts, buf) in pcap:
		try:
			eth = dpkt.ethernet.Ethernet(buf)
			ip = eth.data
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			print()
			print('[+]Src: ' + src + ' Dest: ' + dst)
			if '192.168' in src:
				continue
			else:
				rec1 = reader.city(src)
				rec2 = reader.city(dst)
				city1 = rec1.city.name
				country1 = rec1.country.name
				city2 = rec2.city.name
				country2 = rec2.country.name
				print('[+]Src: ' + str(city1) + ', ' + str(country1) + ' -> Dest: ' + str(city2) + ', ' + str(country2))
				
		except:
			pass
			


def main():
	f = open('/root/Documents/fuzz-2006-07-06-5536.pcap', 'rb')
	pcap = dpkt.pcap.Reader(f)
	print(pcap)
	printPcap(pcap)
	
main()








