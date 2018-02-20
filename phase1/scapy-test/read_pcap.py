from scapy.all import *
from crypt import crypt

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
print(crypted_passwd)

salt = crypted_passwd[:2]

crypted_fluffy = crypt('fluffy', salt)
print(crypted_fluffy)


assert get_obfkey(keyzip_packet.load, 'fluffy') == real_key()

## TODO install pycrypto for AES encryption






