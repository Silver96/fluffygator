import json
import os
import sys
import numpy as np
import ciphers.common

from string import punctuation, digits

default_key = 0

def generate_dictionary(k):
    dictionary = np.array(list("abcdefghijklmnopqrstuvwxy"))
    dictionary = np.reshape(dictionary, (5,5))
    dictionary = np.roll(dictionary, k)
    
    key_dict = {}

    for i in range(5):
        for j in range(5):
            key_dict["%d%d" % (i+1,j+1)] = dictionary[i][j]

    return key_dict

def decipher_plaintext(ciphertext, key_dict):
    result = ""
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i+2]
        if pair in key_dict:
            result += key_dict[pair]
        elif pair == "  ":
            result += " "
        elif pair.strip(" ") in punctuation+digits+"\n":
            result += pair.strip(" ")
        else:
            return None

    return result


def mistery(cipher):

    def do_mistery_decipher(cipher, k):
        key_dict = generate_dictionary(k)
        return decipher_plaintext(cipher, key_dict)

    k = default_key
    result = do_mistery_decipher(cipher, k)
    
    if not result:
        return None

    if not ciphers.common.makes_sense(result):

        for k in range(1, ciphers.common.length):
            result = do_mistery_decipher(cipher, k)
            if ciphers.common.makes_sense(result):
                break

    if not ciphers.common.makes_sense(result):
        return None

    print("--------------------- Used %d offset" % k)
    return result