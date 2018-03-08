import ciphers.common

default_key = 13

def rotk(inner_ciphertext):

    k = default_key

    rotated = ciphers.common.rot(inner_ciphertext, k)
    
    if not ciphers.common.makes_sense(rotated):

        for k in range(ciphers.common.length):
            rotated = ciphers.common.rot(inner_ciphertext, k)
            if ciphers.common.makes_sense(rotated):
                break

    if not ciphers.common.makes_sense(rotated):
        return None

    print("--------------------- Used %d offset" % k)
    return rotated
    