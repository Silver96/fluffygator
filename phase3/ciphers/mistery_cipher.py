import json
import os
import sys

def generate_dictionary():
    dictionary = ["a b c d e",
                  "f g h i j",
                  "k l m n o",
                  "p q r s t",
                  "u v w x y"]

    dictionary = [x.split(" ") for x in dictionary]

    key_dict = {}

    for i in range(5):
        for j in range(5):
            key_dict["%d%d" % (i+1,j+1)] = dictionary[i][j]

    return key_dict

def decipher_plaintext(ciphertext, key_dict):
    result = ""
    try:
        for i in range(0, len(ciphertext), 2):
            pair = ciphertext[i:i+2]
            if pair in key_dict:
                result += key_dict[pair]
            elif pair == "  ":
                result += " "
            else:
                result += pair.strip(" ")

        return result

    except Exception as e:
        print("Exception", e)
        return None


def mistery(cipher):
    key_dict = generate_dictionary()
    return decipher_plaintext(cipher, key_dict)