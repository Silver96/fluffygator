# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
import socket
import argparse
import time
from time import sleep
from datetime import datetime
from datetime import timedelta
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *


MAX_SIZE = 10000

PACKETS_STEP = 6

ROUTER = ('127.0.0.1', 58121) #('128.114.59.42', 5001)


def dump_packet(packet, dst_dir, idx):
    with open('%s/packet%d.pcap' % (dst_dir, idx), 'wb') as p:
        p.write(packet)

    if idx % PACKETS_STEP == 0:
        print("Captured %d packets..." % idx)


def make_timestamp():
    return datetime.now().strftime("%d_%I.%M.%S%p").lower()


def parse_args():

    def valid_dir(dir_name):
         if os.path.isdir(dir_name):
             return dir_name

    # https://stackoverflow.com/questions/25470844/specify-format-for-input-arguments-argparse-python
    def valid_time(string):
        try:
            current = datetime.now()
            arg = datetime.strptime(string, "%H:%M").replace(
                year=current.year, month=current.month, day=current.day)

            if arg - current < timedelta(0):
                arg += timedelta(days=1)

            result = arg - current

            result -= timedelta(microseconds=result.microseconds)

            return result.total_seconds() - 120

        except ValueError:
            raise argparse.ArgumentTypeError(
                "Not a valid date: '%s'." % (string))

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", metavar="hh:mm", type=valid_time, help="time to start capturing (allow 2 mins before that)")
    parser.add_argument("-m", metavar="max_pkts", type=int, help="maximum number of packets to capture")
    parser.add_argument("-p", action='store_true', help="enables the prefilter, discarding packets that don't contain a payload")
    parser.add_argument("--timeout", type=int, help="enables closing connection on timeout after receiving packets")
    parser.add_argument("--working-dir", type=valid_dir)
    return parser.parse_args()


def capture(args):

    max_pkts = args.m
    prefilter = args.p
    timeout = args.timeout

    dst_dir = args.working_dir if args.working_dir else 'packets/%s' % make_timestamp()

    if not args.working_dir:
        if not os.path.isdir('packets'):
            os.mkdir('packets')

        os.mkdir(dst_dir)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

        while sock.connect_ex(ROUTER) != 0:
            sleep(1)

        i = 0
        try:
            print("Started packet capture")
            last_capture = -1

            while True:
                # Capture all packets
                packet = sock.recv(MAX_SIZE)

                if timeout and i > 0 and (time.time()-last_capture) > timeout:
                    print("Timeout exceeded, quitting")
                    break

                last_capture = time.time()

                # If prefiltering is enabled skip packets with no payload
                if prefilter:
                    p_bytes = packet[40:]
                    p = Ether(p_bytes)
                    if not (p or hasattr(p, "load")):
                        continue

                dump_packet(packet, dst_dir, i)

                i += 1

                if max_pkts and i >= max_pkts:
                    print("\nReached max_pkts, quitting")
                    break

        except KeyboardInterrupt:
            print('\nStop capturing packets')


params = parse_args()

if params.t:
    if params.t > 0:
        print("Will start capturing in %d seconds..." % int(params.t))
        sleep(params.t)
    else:
        print("start_time too close (need at least 2 minutes delta), quitting")
        exit(1)

capture(params)
