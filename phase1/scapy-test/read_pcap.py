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


obf_key = get_obfkey(keyzip_packet.load, 'fluffy')

for i in range(0, len(obf_key)-33):
    tmp_key = obf_key[i:i+32]
    if tmp_key == real_deobf_key():
        deobf_key = unhexlify(tmp_key)
        break

iv = unhexlify(iv_packet.load[:-1])

msg = message_packet.load
crypto = AES.new(deobf_key, AES.MODE_CBC, iv)
# msg = crypto.decrypt(msg)
# print(msg)