import argparse
import zipfile

from crypt import crypt

PWLEN = 6

pairs = []

# Get next passwords

def get_new_pw():
    for a in pairs:
        for b in pairs:
            for c in pairs:
                yield a+b+c

# Parse arguments

parser = argparse.ArgumentParser()
args = parser.add_mutually_exclusive_group(required=True)
args.add_argument('-z', metavar="zipfile")
args.add_argument('-p', metavar="encrypted_password")

params = parser.parse_args()

# Obtain character pairs from known passwords

with open("passes", "rt") as file:
    for line in file.readlines():
        line_pairs = [line[i:i+2] for i in range(0, len(line), 2)]

        if "\n" in line_pairs:
            line_pairs.remove("\n")

        for pair in line_pairs:
            if not pair in pairs:
                pairs.append(pair)

# If the user provided a password try to crack it using crypt

if params.p:
    salt = params.p[:2]

    # Cycle through pwds
    for pw in get_new_pw():
        try:
            crypted = crypt(pw, salt)
            if crypted == params.p:
                print(pw)
                break
        except:
            break

# If the user provided a zipfile try to access it

if params.z:
    with zipfile.ZipFile(params.z) as key_zip:

        # Cycle through pwds
        for pw in get_new_pw():
            try:
                with key_zip.open("key", pwd=pw.encode()) as key_file:
                    print(key_file.read())
                    print(pw)
                    break
            except:
                pass