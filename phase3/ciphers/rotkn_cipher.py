import ciphers.common

# default_key = (20, 19, 18, 17)
default_key = (20, 19, 18, 16)

def rotkn(inner_ciphertext):

    k0,k1,k2,k3 = default_key
    rotated = ciphers.common.rot(inner_ciphertext, k0, k1, k2, k3)

    if ciphers.common.makes_sense(rotated):
        print("--------------------- Used (%d %d %d %d) offsets" % (k0, k1, k2, k3))
        return rotated

    n_chars = ciphers.common.length

    for k0 in range(n_chars):
        for k1 in range(n_chars):
            for k2 in range(n_chars):
                for k3 in range(n_chars):

                    rotated = ciphers.common.rot(inner_ciphertext, k0, k1, k2, k3)
                    if ciphers.common.makes_sense(rotated):
                        print("--------------------- Used (%d %d %d %d) offsets" % (k0, k1, k2, k3))
                        return rotated
    return None

    
