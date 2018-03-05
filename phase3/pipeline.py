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
import string

from datetime import datetime
from time import sleep
from binascii import unhexlify

NSA_SERVER = ('128.114.59.42', 2001)

def get_payload(pcap):
    return rdpcap(pcap)[0].load


def get_crypted_passwd(passwd_pcap):
    crypted_passwd = get_payload(passwd_pcap)
    return crypted_passwd.decode().strip('\n')


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
            print('Sending "%s"' % req)
            sock.send(req.encode())
        
            reply = sock.recv(10).decode().strip('\n')
            print('Received "%s"' % reply)


def print_time():
    now = datetime.now().time()
    print("\n------ %d:%d:%d" % (now.hour, now.minute, now.second))


def crack_passwd(crypted_passwd):
    cmd = "python3 cracker_test.py -p " + crypted_passwd
    process = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)
    if not process.returncode:
        return process.stdout.decode().strip("\n")
    else:
        print("failed")
        exit(0)
        return fallback_crack_passwd(crypted_passwd)

def fallback_crack_passwd(crypted_passwd):
    listen_sock, (ip, port) = open_listen_socket(0)

    print_time()
    send_crack_passwd_req(crypted_passwd, port)
    
    sock, _ = listen_sock.accept()

    reply = sock.recv(100).decode()
    
    listen_sock.close()
    sock.close()

    ## reply =  "<crypted_password> <passwd>\n"
    _, passwd = reply.strip('\n').split(' ')

    print('Received passwd = "%s"' % passwd)

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


def possible_keys(obfkey):
    obfkey = obfkey.strip('\n')
    for s in range(0, len(obfkey)-31, 1):
        yield obfkey[s:s+32]

def load_dict():  
    with open('english_dictionary.txt', 'rt') as d:
        words = [line.lower()[:-1] for line in d.readlines()[1:]] ## discard first line comment
        # print('Loaded dictionary of %d words' % len(words))
        return set(words)


def makes_sense(msg):
    dictionary = load_dict()
    words = msg.lower().split(' ')
    count = 0

    for word in words:
        if word in dictionary:
            count += 1

    return count >= 10


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
    

def get_message(ciphertext, obfkey, iv, student_dir):
    print("Finding key...")
    for key in possible_keys(obfkey):
        print(key)
        decrypted_msg = decrypt_ciphertext(ciphertext, key, iv, student_dir)

        if decrypted_msg:
            print('------------- Decryption key', key)
            return decrypted_msg

    # If it gets here without decrypting, report it
    print("-"*20 + "\nNo key worked for %s :(" % student_dir)

def caesar_decrypt(inner_ciphertext):

    lower_alphabet = string.ascii_lowercase
    upper_alphabet = string.ascii_uppercase

    def shift(c, k, alphabet):
        i = alphabet.index(c)
        i = (i + k) % len(alphabet)
        return alphabet[i]

    def rot(k):
        rotated = []
        for c in inner_ciphertext:
            if c in lower_alphabet:
                rotated.append(shift(c, k, lower_alphabet))
            elif c in upper_alphabet:
                rotated.append(shift(c, k, upper_alphabet))
            else:
                rotated.append(c)

        return "".join(rotated)

    for k in range(len(lower_alphabet)):
        rotated = rot(k)
        # print(rotated)
        if makes_sense(rotated):
            return rotated


def save_passwd(passwd, student_dir):
    with open(student_dir + "/passwd.plain", "wt") as file:
        file.write(passwd)

def test_plaintexts():
    try:
        with open('%s/plaintext1' % student_dir, "rt") as file:
            file.read()
        with open('%s/plaintext2' % student_dir, "rt") as file:
            file.read()
        with open('%s/plaintext3' % student_dir, "rt") as file:
            file.read()
        return True
    except:
        return False

def main(passwd):

    passwd_pcap  = '%s/passwd.pcap'  % student_dir
    keyzip_pcap  = '%s/zip.pcap' % student_dir
    iv_pcap      = '%s/iv.pcap'      % student_dir
    message1_pcap = '%s/ciphertext1.pcap' % student_dir
    message2_pcap = '%s/ciphertext2.pcap' % student_dir
    message3_pcap = '%s/ciphertext3.pcap' % student_dir


    if not passwd:
        crypted_passwd = get_crypted_passwd(passwd_pcap)
        # print('crypted_passwd', crypted_passwd)

        passwd = crack_passwd(crypted_passwd)
        save_passwd(passwd, student_dir)
        # print('passwd', passwd)

    obfkey = get_obfkey(get_payload(keyzip_pcap), passwd)
    # print('obfkey', obfkey)

    iv = get_payload(iv_pcap).decode().strip('\n')
    # print('iv', iv)

    ciphertext1 = get_payload(message1_pcap)
    ciphertext2 = get_payload(message2_pcap)
    ciphertext3 = get_payload(message3_pcap)

    message1 = get_message(ciphertext1, obfkey, iv, student_dir)
    message2 = get_message(ciphertext2, obfkey, iv, student_dir)
    message3 = get_message(ciphertext3, obfkey, iv, student_dir)

    if message1 is None or message2 is None or message3 is None:
        exit(2)

    print("Plaintext obtained for " + student_dir)
    # print('MESSAGE')
    # print("message1", message1)
    # print("message2", message2)
    # print("message3", message3)

    # print('plaintext saved in tmp/plaintext')

    with open('%s/plaintext1' % student_dir, "wt") as file:
        file.write(message1)
    with open('%s/plaintext2' % student_dir, "wt") as file:
        file.write(message2)
    with open('%s/plaintext3' % student_dir, "wt") as file:
        file.write(message3)


def decipher_plaintexts():

    with open('%s/plaintext1' % student_dir, "rt") as file:
        cipher = file.read()
        plaintext = caesar_decrypt(cipher)
        with open('%s/true_plaintext1' % student_dir, "wt") as file_true:
            file_true.write(plaintext)
            print("Deciphered plaintext1 saved for %s!" % student_dir)

if len(sys.argv) < 2:
    print("Usage: %s student_dir" % sys.argv[0])
    exit(1)

passwd = None

if len(sys.argv) == 3:
    passwd = sys.argv[2]

student_dir = sys.argv[1]

if not test_plaintexts():
    main(passwd)
decipher_plaintexts()