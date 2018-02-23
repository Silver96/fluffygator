# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

p_dir = "fileprof"
cruzid = ""

def print_p_info(packet):
    print("%s:%s ~> %s:%s [%d bytes]" % (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport, len(packet.load)))

packets = [
    rdpcap('../'+p_dir+'/'+cruzid+("." if len(cruzid)>0 else "")+'passwd.pcap')[0],
    rdpcap('../'+p_dir+'/'+cruzid+("." if len(cruzid)>0 else "")+'key.zip.pcap')[0],
    rdpcap('../'+p_dir+'/'+cruzid+("." if len(cruzid)>0 else "")+'iv.pcap')[0],
    rdpcap('../'+p_dir+'/'+cruzid+("." if len(cruzid)>0 else "")+'message.pcap')[0]
]

for p in packets:
    print_p_info(p)

# Fileprof:
# packets from 172.217.6.46 to 151.101.192.81:2002 -> password, zipfile
# packets from 172.217.6.46 to 151.101.192.81:2001 -> iv, ciphertext

# Cruzid files (Andrea):
# packets from 172.217.6.46 to 151.101.192.81:2001 -> password, zipfile, iv
# packet from 128.114.59.29 to 128.114.59.29:2001 -> ciphertext
