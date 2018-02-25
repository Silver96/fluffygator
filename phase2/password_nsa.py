from scapy.all import *
from crypt import crypt

import zipfile
import io

import sys
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


def send_crack_passwd_req(crypted_passwds, port):    
    for crypted_passwd in crypted_passwds:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            
            while sock.connect_ex(NSA_SERVER) != 0:
                sleep(1)

            req = "%s 128.114.59.29 %d" % (crypted_passwd, port)
            
            reply = None
            while not reply == 'OK':
                print('Sending "%s"' % req)
                sock.send(req.encode())
                reply = sock.recv(10).decode().strip('\n')
                print('Received "%s"' % reply)
                sleep(2)


def print_time():
    now = datetime.now().time()
    print("\n------ %d:%d:%d" % (now.hour, now.minute, now.second))


def crack_passwds(crypted_passwds):
    listen_sock, (ip, port) = open_listen_socket(51247)

    print_time()
    send_crack_passwd_req(crypted_passwds, port)
    
    sock, _ = listen_sock.accept()
    
    passwds = {}
    for _ in range(len(crypted_passwds)):
        reply = sock.recv(100).decode()
        print(reply)

        ## reply =  "<crypted_password> <passwd>\n"
        # crypted, passwd = reply.split(' ')
        # passwds[crypted] = passwd

        # print('Received passwd = "%s"' % passwd)

    listen_sock.close()
    sock.close()

    return passwds

def get_crypted_passwds(dir_name):

    crypted_passwds = []

    for student_id in range(len(os.listdir(dir_name))):
        passwd_pcap = "%s/%d/passwd.pcap" % (dir_name, student_id)
        crypted_passwd = rdpcap(passwd_pcap)[0].load.decode().strip('\n')
        crypted_passwds.append(crypted_passwd)

    return crypted_passwds

def main():
    if len(sys.argv) < 2:
        print("Usage: %s dir_name" % sys.argv[0])
        exit(1)

    students_dir = sys.argv[1]

    crypted_passwds = get_crypted_passwds(students_dir)
    passwds = crack_passwds(crypted_passwds)

    for i, crypted in enumerate(crypted_passwds):
        with open("%s/%d/passwd.plain" % (students_dir, i), "wt") as file:
            file.write(passwds[crypted])

main()