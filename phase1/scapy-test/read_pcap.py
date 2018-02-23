# Suppress scapy warning regarding ipv6
# https://stackoverflow.com/questions/24812604/hide-scapy-warning-message-ipv6
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from crypt import crypt
from Crypto.Cipher import AES
from binascii import unhexlify, hexlify, b2a_hqx

import zipfile
import io

from binascii import unhexlify

from Crypto.Cipher import AES

# rdpcap comes from scapy and loads in our pcap file
passwd_packet = rdpcap('../passwd.pcap')[0]
keyzip_packet = rdpcap('../key.zip.pcap')[0]
iv_packet = rdpcap('../iv.pcap')[0]
message_packet = rdpcap('../message.pcap')[0]

def get_payload(packet):
    return packet.load.decode('ascii').strip('\n')

def real_key():
    with open('../key', 'r') as k:
        return k.read().strip('\n')

def real_deobf_key():
    with open('../key.plain', 'r') as k:
        return k.read().strip('\n')    

def get_obfkey(key_payload, passwd):
    try:
        passwd = passwd.encode()
    except:
        pass
    with zipfile.ZipFile(io.BytesIO(key_payload)) as archive:
        with archive.open('key', pwd=passwd) as key_file:
            key_file_content = key_file.read().decode().strip('\n')
            return key_file_content

crypted_passwd = get_payload(passwd_packet)

salt = crypted_passwd[:2]

crypted_fluffy = crypt('fluffy', salt)

# print(crypted_fluffy)


assert get_obfkey(keyzip_packet.load, 'fluffy') == real_key()

## TODO install pycrypto for AES encryption

def get_file_content(filename):
    with open(filename, 'r') as f:
        return f.read().strip('\n')

iv = unhexlify(iv_packet.load[:-1])

# print('iv len(%d)' % len(iv), iv)

keystr = get_file_content('../key.plain')
# print('keystr', keystr)
key = unhexlify(keystr)
# print('key len(%d)' % len(key), key)


aes1 = AES.new(key, AES.MODE_CBC, iv)

hellocipher1 = aes1.encrypt(b"CMPS122 is an awesome class!    ")

aes2 = AES.new(key, AES.MODE_CBC, iv)

hellocipher2 = aes2.encrypt(b"CMPS122 is an awesome class!\x1c\x1c\x1c\x1c")

print('1', hellocipher1)
print('2', hellocipher2)
