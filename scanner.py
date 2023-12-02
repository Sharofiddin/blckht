from ctypes import *
import ipaddress
import os
import socket
import struct
import sys
import threading
import time 

MESSAGE= 'GOSLEEEP!'

class IP(Structure):
    _fields_ = [
        ("ver", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        ("tos",c_ubyte ,8 ),
        ("len",c_ushort ,16 ),
        ("id",c_ushort ,16),
        ("offset",c_ushort ,16 ),
        ("ttl",c_ubyte , 8),
        ("protocol_num",c_ubyte , 8),
        ("sum",c_ushort , 16),
        ("src",c_uint32 , 32),
        ("dst",c_uint32 , 32) 
    ]
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
        self.protocol_map = {1:"ICMP",  6 :"TCP", 17:"UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s %s' % (e,self.protocol_num))
            self.protocol = str(self.protocol)
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]
def udp_sender(subnet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(subnet).hosts():
            sender.sendto(bytes(MESSAGE,'utf-8'), (str(ip), 65212))
class Scanner:

  def __init__(self, host, subnet):
    self.host = host
    self.subnet = subnet
    socket_protocol = socket.IPPROTO_ICMP
    self.socket =  socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    self.socket.bind((host, 0))
    self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
  def sniff(self):
    hosts_up = set([f'{str(self.host)} *'])
    try:
      while True:
        raw_buffer = self.socket.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        if ip_header.protocol == 'ICMP':
           offset = ip_header.ihl * 5
           buff = raw_buffer[offset : offset + 8]
           icmp_header = ICMP(buff)
           if icmp_header.code == 3 and icmp_header.type == 3:
             if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(subnet):
               tgt = str(ip_header.src_address)
               if tgt != self.host and tgt not in hosts_up:
                 hosts_up.add(tgt)
                 print(f'Host up: {tgt}') 
    except KeyboardInterrupt:
      print('User interrupted')
      if hosts_up:
        print(f'\n\nSummary hosts up in {self.subnet}')
        for host in sorted(hosts_up):
            print(f'{host}')
      print('')
      sys.exit()

if __name__ == '__main__':
    argc = len(sys.argv)
    if  argc >= 2:
      host = sys.argv[1]
      if argc > 2:
        subnet = sys.argv[2]
      else:
        print ('Enter subnet')
        subnet = input()
    else:
      print('Enter host IP: ')
      host = input()
      print('Enter subnet:')
      subnet = input()
    scanner = Scanner(host, subnet)
    time.sleep(5)
    t = threading.Thread(target=udp_sender, args=[subnet])
    t.start()
    scanner.sniff()

