# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from crypt import crypt

import zipfile
import io
import time
import os

import sys
import socket
from datetime import datetime

from time import sleep


MAX_SIZE = 10000

ROUTER = ('128.114.59.42', 5001)


def dump_packet(packet, timestamp, idx):
    with open('passwds/%s/passwd%07d.pcap' % (timestamp, idx), 'wb') as p:
        p.write(packet)


def make_timestamp():
    ## DayOfMonth_HH.MM[am|pm]
    return datetime.now().strftime("%d_%I.%M%p").lower()


def is_passwd_packet(packet):
    filename = 'passwds/tmp.pcap'
    with open(filename, 'wb') as p:
        p.write(packet)
    packet = rdpcap(filename)[0]
    try:
        length = len(packet.load)
        print(length)
        return length == 13 + 1
    except:
        return False


def capture():

    timestamp = make_timestamp()

    # os.system('mkdir passwds/')

    passwd_file = open('passwds/passwds%s' % timestamp, 'wt')
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        while sock.connect_ex(ROUTER) != 0:
            sleep(1)

        i = 0
        try:
            while True:
                ## Capture all packets
                print('Waiting packet #%d' % i)            

                ## TODO might read more than one at the same time?
                packet = sock.recv(MAX_SIZE)[40:]

                packet = Ether(packet)

                if hasattr(packet, "load"):
                    if len(packet.load) == 14:
                        passwd_file.write(packet.load.decode())
                        passwd_file.flush()
                        os.fsync(passwd_file.fileno())
                        print('Received PASSWD packet #%d' % i)
                else:
                    print('Received packet #%d' % i)

                i += 1

        except KeyboardInterrupt:
            passwd_file.close()
            print('\nStop capturing packets')

capture()
