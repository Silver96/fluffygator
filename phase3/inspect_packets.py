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
import argparse

from datetime import datetime
from time import sleep
from itertools import count

def parse_args():

    def valid_dir(dir_name):
        if os.path.isdir(dir_name):
            return dir_name
        raise argparse.ArgumentTypeError("%s is not a valid path" % dir_name)

    parser = argparse.ArgumentParser()
    parser.add_argument("capture_dir", type=valid_dir, help="Directory containing the packets to inspect")
    parser.add_argument("tuples_count", type=int, help="Number of tuples to collect from the packets directory")
    parser.add_argument("msg_count", type=int, help="Number of messages per tuple")

    return parser.parse_args()

def inspect(packet_dir, msg_count, tuples_count):

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

    idxs = []
    for i, packet in enumerate(all_packets(packet_dir)):
        try:
            payload_len = len(packet.load)
            if payload_len < 14:
                continue
            idxs.append(i)
        except:
            pass

    pkts_per_tuple = 3 + msg_count
    student_tuples = [idxs[i:i+pkts_per_tuple] for i in range(0, len(idxs), pkts_per_tuple)]

    base_dir = 'students/' + os.path.basename(os.path.normpath(packet_dir)) + "/"
    os.mkdir(base_dir)

    for i, t in enumerate(student_tuples):
        student_dir = base_dir + str(i) + '/'
        os.mkdir(student_dir)
        names = ['passwd', 'zip', 'iv'] + ['ciphertext%d' % x for x in range(pkts_per_tuple-3)]
        for packet_idx, new_file in zip(t, names):
            pname = make_pname(packet_dir, packet_idx)
            new_pname = student_dir + new_file + '.pcap'
            os.system('cp %s %s' % (pname, new_pname))

        print("%s succesfully generated" % student_dir)

        if i == tuples_count:
            break

args = parse_args()

inspect(args.capture_dir, args.msg_count, args.tuples_count)
