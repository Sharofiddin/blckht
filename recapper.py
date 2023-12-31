from scapy.all import TCP, rdpcap
import collections
import os
import re
import sys
import zlib

OUTDIR = '/home/sharofiddin/Desktop/pictures'
PCAPS = '/home/sharofiddin/Downloads'

Response = collections.namedtuple('Response', ['header', 'payload'])

def get_header(payload):
    try:
        header_raw = payload[:payload.index(b'\r\n\r\n') +2]
    except ValueError:
        sys.stdout.write('-')
        sys.stdout.flush()
        return None
    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode()))
    if 'Content-Type' not in header :
        return None
    return header

def extract_content(Response, content_name='image'):
    content, content_type = None, None
    if content_name in Response.header['Content-Type']:
        content_type = Response.header['Content-Type'].split('/')[1]
        sys.stdout.write(content_type + '\n')
        sys.stdout.flush()
        content = Response.payload[Response.payload.index(b'\r\n\r\n')+4:]

        if 'Content-Encoding' in Response.header:
            if Response.header['Content-Encoding'] == 'gzip':
                content = zlib.decompress(content, zlib.MAX_WBITS | 32)
            elif Response.header['Content-Encoding'] == 'deflate':
                content = zlib.decompress(content)
    return content, content_type


HTTP_PORTS = [80,8080,3000, 8081, 8082]

class Recapper:
    def __init__(self, fname) -> None:
        pcap = rdpcap(fname)
        self.sessions = pcap.sessions()
        self.responses = list()
    def get_responses(self):
        for session in self.sessions:
            payload = b''
            for packet in self.sessions[session]:
                try:
                   if packet[TCP].dport in HTTP_PORTS or packet[TCP].sport in HTTP_PORTS:
                       payload += bytes(packet[TCP].payload)
                       sys.stdout.write('o')
                       sys.stdout.flush()
                except IndexError as ex:
                    sys.stdout.write('x')
                    sys.stdout.flush()

            if payload:
               header = get_header(payload)
               if header is None:
                  continue
               self.responses.append(Response(header=header, payload=payload))   
    def write(self, content_name):
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response, content_name)
            if content and content_type:
                fname = os.path.join(OUTDIR, f'ex_{i}.{content_type}')
                print(f'Writing {fname}')
                with open(fname, 'wb') as f:
                    print(fname)
                    f.write(content) 

if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'pcap.pcap')
    recapper = Recapper(pfile)
    recapper.get_responses()
 
    recapper.write(input('\ncontent type:'))
