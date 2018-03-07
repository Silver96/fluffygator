import json
import os
import sys

def generate_dictionary():
    test_plaintext = [
    "Is it thy will thy image should keep open",
    "My heavy eyelids to the weary night",
    "Dost thou desire my slumbers should be broken",
    "While shadows like to thee do mock my sight",
    "Is it thy spirit that thou sendst from thee",
    "So far from home into my deeds to pry",
    "To find out shames and idle hours in me",
    "The scope and tenure of thy jealousy",
    "O no thy love though much is not so great",
    "It is my love that keeps mine eye awake",
    "Mine own true love that doth my rest defeat",
    "To play the watchman ever for thy sake",
    "  For thee watch I whilst thou dost wake elsewhere",
    "  From me far off with others all too near"
    ]

    test_plaintext = "\n".join(test_plaintext)

    key_dict = {}

    test_ciphertext = ""

    with open("ciphers/cipher3", "rt") as file:
        for line in file.readlines():
            # line = line.strip(" \n")
            test_ciphertext += line

    print(test_ciphertext)

    for i, c in enumerate(test_plaintext):
        c = c.lower()
        pair = test_ciphertext[2*i:2*i+2]
        # print(pair)
        if pair in key_dict:
            # print(pair, c, key_dict)
            assert key_dict[pair] == c
        else:
            key_dict[pair] = c

    for i in range(0, len(test_ciphertext), 2):
        pair = test_ciphertext[i:i+2]
        print(key_dict[pair], end="")

    with open("ciphers/key_dict", "wt") as file:
        json.dump(key_dict, file)

def decipher_plaintext(filename, key_dict):
    ciphertext = ""

    with open(filename, "rt") as f_in:
        for line in f_in.readlines():
            ciphertext += line

    with open(filename+"_deciphered", "wt") as f_out:
        for i in range(0, len(ciphertext), 2):
            pair = ciphertext[i:i+2]
            print(key_dict[pair], end="")
            f_out.write(key_dict[pair])

# if not os.path.isfile("key_dict"):
#     generate_dictionary()

# key_dict = None
# with open("ciphers/key_dict", "rt") as file:
#     key_dict = json.load(file)

# decipher_plaintext(sys.argv[1], key_dict)