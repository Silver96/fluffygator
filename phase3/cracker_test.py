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

def crack_crypted_pw(crypted_pw):
    salt = crypted_pw[:2]

    # Cycle through pwds
    for pw in get_new_pw():
        try:
            crypted = crypt(pw, salt)
            if crypted == crypted_pw:
                return pw
        except:
            break

def crack_zip(zipfile):
    with zipfile.ZipFile(zipfile) as key_zip:

        # Cycle through pwds
        for pw in get_new_pw():
            try:
                with key_zip.open("key", pwd=pw.encode()) as key_file:
                    print(key_file.read())
                    return pw
            except:
                pass

# Parse arguments

parser = argparse.ArgumentParser()
args = parser.add_mutually_exclusive_group(required=True)
args.add_argument('-z', metavar="zipfile")
args.add_argument('-p', metavar="encrypted_password")

params = parser.parse_args()

passes = ""

# Obtain character pairs from known passwords

with open("passes", "rt") as file:
    for line in file.readlines():
        line_pairs = [line[i:i+2] for i in range(0, len(line), 2)]

        if "\n" in line_pairs:
            line_pairs.remove("\n")

        for pair in line_pairs:
            if not pair in pairs:
                pairs.append(pair)

    # file.seek(0)
    # passes = file.read()

# If the user provided a password try to crack it using crypt

if params.p:

    if params.p == 'parg1/WTS.A8E':
        exit()

    result = crack_crypted_pw(params.p)
    if result == None:
        # print("failed")
        exit(1)
    else:
        print(result)
        exit(0)        
        # print("new" if passes.find(result) == -1 else "known")


# If the user provided a zipfile try to access it

if params.z:
    print(crack_zip(params.z))