# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from crypt import crypt

import zipfile
import io
import time

import sys
import socket
from datetime import datetime

from time import sleep


MAX_SIZE = 10000

ROUTER = ('128.114.59.42', 5001)


def dump_packet(packet, timestamp, idx):
    with open('packets/%d/packet%d.pcap' % (timestamp, idx), 'wb') as p:
        p.write(packet)


def capture():

    timestamp = time.time()

    os.system('mkdir packets/%d' % timestamp)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        while sock.connect_ex(ROUTER) != 0:
            sleep(1)

        i = 0
        try:
            while True:
                ## Capture all packets
                print('Waiting packet #%d' % i)            

                ## TODO might read more than one at the same time?
                packet = sock.recv(MAX_SIZE)
                dump_packet(packet, timestamp, i)

                print('Received packet #%d' % i)
                i += 1
        except KeyboardInterrupt:
            print('\nStop capturing packets')

capture()
