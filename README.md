# Fluffygator
This repo contains a bunch of code me and [Lorenzo Selvatici](https://github.com/LorenzSelv) worked on while attending [CMPS122](https://cmps122-winter18-01.courses.soe.ucsc.edu/home) at UCSC.

## Purpose
This code was used in order to complete the last lab assignment for the course, which consisted of different phases with specific goals that had to be achieved.

## Content
The repo is divided into 4 phase directories, each one containing code specific for that phase. Since all phases are connected, some of it has been simply copied over between directories. 

### phase1
The goal for the first phase was to be able to obtain and decrypt some ciphertext obtainable from given network capture files (.pcap format). The real purpose was to begin setting up an _automated process_ (or _pipeline_, as we called it) that allowed us to obtain the plaintext just by giving the .pcap files as input, with no need for user interaction. 

The process consisted of 4 steps:
1. Obtaining the _obfuscated key_: one of the .pcap files contained a password-protected zipped version of a textfile, where a long string was stored. This string contained (at a random position) the key that we needed to decrypt the ciphertext associated. Before being able to access the _obfuscated key_ we needed to crack the zip password, which at first was achieved through bruteforce
2. Obtaining _IV_: another .pcap file contained the _IV_ (initial vector) necessary for decrypting the ciphertext; we simply grabbed it from the .pcap payload
3. Obtaining _ciphertext_: same as _IV_, we grabbed the ciphertext from its packet payload
4. Putting it all together -> obtaining plaintext: the last step consisted in making a C program over and over again, until it was able to decrypt the ciphertext. We needed to write the decryption part in C since we had issues with decryption through pycrypto, due to some settings we weren't able to determine. The C program took a _decryption key_, an _IV_ and a _ciphertext_ and tried to decrypt it, returning its result. We iterated through the _obfuscated key_ and passed each subestring to the C program in order to test all possible keys, stopping once a succesful one was found.

### phase2
The second phase was different from the first one due to the fact that packets had to be "captured". The instructor had setup a server which broadcasted .pcap files every now and then, and we had to open a socket and listen for this .pcap files in order to capture, save and run our _pipeline_ on them. The password for the zipfiles could be asked to a service the instructor provided, which would be ok for this phase but really uneffective for the following ones.

(TO BE CONTINUED)
