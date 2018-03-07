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
import time

from datetime import datetime
from time import sleep
from itertools import count

def make_pname(packet_dir, idx):
    return '%s/packet%d.pcap' % (packet_dir, idx)
    

def get_packet(idx, packet_dir):
    pname = make_pname(packet_dir, idx)
    packets = rdpcap(pname)
    return packets[0]

def all_packets(packet_dir):
    for idx in count(0):
        pname = make_pname(packet_dir, idx)
        
        if not os.path.exists(pname):
            raise StopIteration

        packets = rdpcap(pname)
        assert(len(packets) == 1)
        yield packets[0]

def inspect(packet_dir):
    idxs = []
    for i, packet in enumerate(all_packets(packet_dir)):
        try:
            payload_len = len(packet.load)
            idxs.append(i) 
        except:
            pass

    # print('packet idxs len', len(idxs))

    pkts_per_student = 6
    student_tuples = [idxs[i:i+pkts_per_student] for i in range(0, len(idxs), pkts_per_student)]

    timestamp = time.time()
    base_dir = 'students/' + os.path.basename(packet_dir) + "/"
    os.mkdir(base_dir)

    for i, t in enumerate(student_tuples):
        # crypted, zip, iv, ciphertext
        student_dir = base_dir + str(i) + '/'
        os.mkdir(student_dir)
        names = ['passwd', 'zip', 'iv'] + ['ciphertext%d' % x for x in range(pkts_per_student-3)]
        for packet_idx, new_file in zip(t, names):
            pname = make_pname(packet_dir, packet_idx)
            new_pname = student_dir + new_file + '.pcap'
            os.system('cp %s %s' % (pname, new_pname))

        if i == 65:
            break
    


if len(sys.argv) < 2:
    print('Usage %s packet_dir' % __file__)
    exit(1)

inspect(sys.argv[1])
