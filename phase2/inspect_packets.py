# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from crypt import crypt

import zipfile
import io

import sys
import socket

from datetime import datetime
from time import sleep
from itertools import count


def all_packets(start=0):
    for idx in count(start):
        pname = 'packets/packet%d.pcap' % idx
        
        if not os.path.exists(pname) or idx==4:
            raise StopIteration

        packets = rdpcap(pname)
        assert(len(packets) == 1)
        yield packets[0]


def inspect(start=0):
    for packet in all_packets(start):
        print(packet.payload)

inspect()
