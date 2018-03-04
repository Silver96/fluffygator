# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
import socket
import argparse
from time import sleep
from datetime import datetime
from datetime import timedelta
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *


MAX_SIZE = 10000

ROUTER = ('128.114.59.42', 5001)


def dump_packet(packet, timestamp, idx):
    with open('packets/%s/packet%d.pcap' % (timestamp, idx), 'wb') as p:
        p.write(packet)


def make_timestamp():
    return datetime.now().strftime("%d_%I.%M.%S%p").lower()


def parse_args():
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
    return parser.parse_args()


def capture(max_pkts=None, prefilter=False):

    timestamp = make_timestamp()

    os.system('mkdir packets/%s' % timestamp)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

        while sock.connect_ex(ROUTER) != 0:
            sleep(1)

        i = 0
        try:
            print("Started packet capture!")
            while True:
                # Capture all packets
                packet = sock.recv(MAX_SIZE)

                # If prefiltering is enabled skip packets with no payload
                if prefilter:
                    p_bytes = packet[40:]
                    p = Ether(p_bytes)
                    if not (p or hasattr(p, "load")):
                        continue

                dump_packet(packet, timestamp, i)

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

capture(params.m, params.p)
