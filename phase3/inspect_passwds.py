# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from crypt import crypt

import zipfile
import io

import sys
import signal
import socket
from datetime import datetime

from time import sleep

from binascii import unhexlify

NSA_SERVER = ('128.114.59.42', 2001)

def open_listen_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    return sock, sock.getsockname() ## return the (ip, port)


def send_crack_passwd_req(crypted_passwd, port):    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        while sock.connect_ex(NSA_SERVER) != 0:
            sleep(1)

        req = "%s 128.114.59.29 %d" % (crypted_passwd, port)
        
        reply = None
        while not reply == 'OK':
            # print('Sending "%s"' % req)
            sock.send(req.encode())
            reply = sock.recv(10).decode().strip('\n')
            # print('Received "%s"' % reply)
            # sys.stdout.flush()
            sleep(2)


def print_time():
    now = datetime.now().time()
    print("\n------ %d:%d:%d" % (now.hour, now.minute, now.second))


def crack_passwd(crypted_passwd):
    listen_sock, (ip, port) = open_listen_socket(0)

    # print_time()
    send_crack_passwd_req(crypted_passwd, port)
    
    sock, _ = listen_sock.accept()
    
    reply = sock.recv(100).decode()
    print(reply.strip('\n'))
    sys.stdout.flush()

    listen_sock.close()
    sock.close()



def main():
    # python3 inspect_passwds.py passwds/passwds03_05.57pm | tee passwds/passwd.plain
    if len(sys.argv) != 2:
        print("Usage: %s passwds_file" % sys.argv[0])
        exit(1)

    MAX_NUM_PROCESSES = 10 
    num_processes = 0

    file = open(sys.argv[1], 'rt')

    # https://stackoverflow.com/questions/3290292/read-from-a-log-file-as-its-being-written-using-python
    while True:
        where = file.tell()
        line  = file.readline()
        if not line:
            time.sleep(1)
            file.seek(where)
        else:
            time.sleep(5)
            if num_processes == MAX_NUM_PROCESSES:
                for _ in range(10):
                    pid, _ = os.wait()
                    # print('wait', pid)
                num_processes = 0
                time.sleep(60*2)

            num_processes += 1
            if os.fork() == 0:
                crack_passwd(line.strip('\n'))
                exit(0)


main()
