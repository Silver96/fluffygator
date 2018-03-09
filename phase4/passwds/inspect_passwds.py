# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from crypt import crypt

import sys
import socket
from datetime import datetime

from time import sleep

from passwd_cracker import PasswdCracker

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


def crack_passwd_nsa(crypted_passwd):
    listen_sock, (ip, port) = open_listen_socket(0)

    # print_time()
    send_crack_passwd_req(crypted_passwd, port)
    
    sock, _ = listen_sock.accept()
    
    reply = sock.recv(100).decode()
    passwd = reply.strip(' \n')
    print(passwd)
    sys.stdout.flush()

    listen_sock.close()
    sock.close()
    return passwd



def main():
    # python3 inspect_passwds.py passwds/passwds03_05.57pm | tee passwds/passwd.plain
    if len(sys.argv) != 2:
        print("Usage: %s passwds_file" % sys.argv[0])
        exit(1)

    MAX_NUM_PROCESSES = 10 
    num_processes = 0

    cracker = PasswdCracker()

    crypted_file = open(sys.argv[1], 'rt')
    
    nsa_counter = 0
    # https://stackoverflow.com/questions/3290292/read-from-a-log-file-as-its-being-written-using-python
    while True:
        where = crypted_file.tell()
        line  = crypted_file.readline()

        if not line:
            time.sleep(1)
            crypted_file.seek(where)
            continue

        time.sleep(5)
        crypted = line.strip(' \n')

        passwd = cracker.crack(crypted)
        if passwd:
            print('cracked')
            continue

        print('-'*20 + ' NSA %d' % nsa_counter)
        nsa_counter += 1

        if num_processes == MAX_NUM_PROCESSES:
            for _ in range(10):
                pid, _ = os.wait()
                # print('wait', pid)
            num_processes = 0
            time.sleep(20)

        num_processes += 1
        if os.fork() == 0:
            passwd = crack_passwd_nsa(crypted)
            cracker.append_to_dictionary(passwd)
            exit(0)

        ## Reload the dictionary for parent main process
        cracker.reload_dictionary()


main()
