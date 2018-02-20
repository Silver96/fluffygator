# NOTES

- packet dissecting: scapy
- AES encryption/decryption: C? (lookup python solutions)

- pipeline: 
    extract payload from .pcap
    detect size and payload type -> react accordingly
        **password**: crack encryption
        zip: use cracked password, obtain obfuscated AES key    
        iv: store for decryption
        message: decrypt through iv and AES key (test each key obtainable from obfuscated key file)
    save decrypted message