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
import ciphers

import argparse

from datetime import datetime
from time import sleep
from passwds.passwd_cracker import PasswdCracker

NSA_SERVER = ('128.114.59.42', 2001)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("student_dir", help="Working directory for the script")
    parser.add_argument("msg_count", type=int, help="Number of ciphertext messages")
    parser.add_argument("-p", metavar="password", help="Password (used instead of password cracking)")

    return parser.parse_args()

def get_payload(pcap):
    return rdpcap(pcap)[0].load


def get_passwd(passwd_pcap):
    crypted_passwd = get_payload(passwd_pcap).decode().strip('\n')

    cracker = PasswdCracker()
    passwd = cracker.crack(crypted_passwd)

    if not passwd:
        passwd = cracker.crack_nsa(crypted_passwd)

    return passwd

def get_obfkey(key_payload, passwd):
    try:
        passwd = passwd.encode()
    except:
        pass
    with zipfile.ZipFile(io.BytesIO(key_payload)) as archive:
        with archive.open('key', pwd=passwd) as key_file:
            key_file_content = key_file.read().decode().strip('\n')
            return key_file_content

def decrypt_ciphertext(ciphertext, key, iv, student_dir):
    cipherfile = student_dir + "/ciphertext" 
    textfile   = student_dir + "/plaintext"

    with open(cipherfile, 'wb') as ct:
        ct.write(ciphertext)

    cmd = 'decryptor/decrypt %s %s %s %s' % (key, iv, cipherfile, textfile)

    try:
        proc = subprocess.run(cmd.split(' '), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if proc.returncode != 0:
            return None
        with open(textfile, 'rt') as pt:
            return pt.read()
    except Exception as e:
        ## When decrypting with the wrong key, the program abort
        # print("exception", e)
        return None
    
def get_message(ciphertext, obfkey, iv, student_dir, AES_key):

    def possible_keys(obfkey):
        if AES_key:
            yield AES_key

        obfkey = obfkey.strip('\n')
        for s in range(0, len(obfkey)-31, 1):
            yield obfkey[s:s+32]

    print("Finding key...")
    for key in possible_keys(obfkey):
        decrypted_msg = decrypt_ciphertext(ciphertext, key, iv, student_dir)
        print(key)
        if decrypted_msg:
            print('------------- Decryption key', key)
            return decrypted_msg, key

    # If it gets here without decrypting, report it
    print("-"*20 + "\nNo key worked for %s :(" % student_dir)

def save_passwd(passwd, student_dir):
    with open(student_dir + "/passwd.plain", "wt") as file:
        file.write(passwd)

# Test if plaintext have already been obtained
def test_plaintexts():
    try:
        for i in range(msg_count):
            with open('%s/plaintext%d' % (student_dir, i), "rt") as file:
                file.read()

        return True
    except:
        return False

def get_plaintexts(passwd):

    passwd_pcap  = '%s/passwd.pcap'  % student_dir
    keyzip_pcap  = '%s/zip.pcap' % student_dir
    iv_pcap      = '%s/iv.pcap'      % student_dir

    if not passwd:
        passwd = get_passwd(passwd_pcap)
        save_passwd(passwd, student_dir)

    obfkey = get_obfkey(get_payload(keyzip_pcap), passwd)
    AES_key = None

    iv = get_payload(iv_pcap).decode().strip('\n')

    for i in range(msg_count):

        message_pcap = '%s/ciphertext%d.pcap' % (student_dir, i)
        ciphertext = get_payload(message_pcap)

        message, AES_key = get_message(ciphertext, obfkey, iv, student_dir, AES_key)

        if message is None:
            exit(2)

        with open('%s/plaintext%d' % (student_dir, i), "wt") as file:
            file.write(message)

        print("Plaintext %d obtained for %s" % (i, student_dir))

def decipher_plaintexts():

    def save_true_plaintext(idx, text):
        with open('%s/true_plaintext%d' % (student_dir, idx), "wt") as file:
            file.write(text)
            print("Deciphered plaintext%d saved for %s" % (idx, student_dir))

    def decipher_plaintext(i):
        with open('%s/plaintext%d' % (student_dir, i), "rt") as file:
            cipher = file.read()

            plaintext = ciphers.rotk(cipher)

            if not plaintext:
                plaintext = ciphers.rotkn(cipher)

            if not plaintext:
                plaintext = ciphers.mistery(cipher)

            if not plaintext:
                print("-" * 20 + "Failed " + student_dir)
                exit(1)
            
            save_true_plaintext(i, plaintext)

    start_decipher = time.time()

    for i in range(msg_count):
        
        tmp_time = time.time()

        decipher_plaintext(i)

        decipher_end = time.time()
        print("plaintext%d deciphered in %f seconds" % (i, decipher_end-tmp_time))

    print("Deciphering completed in %f seconds" % (time.time()-start_decipher))

args = parse_args()

student_dir = args.student_dir
msg_count = args.msg_count

if not test_plaintexts():
    get_plaintexts(args.p)

decipher_plaintexts()