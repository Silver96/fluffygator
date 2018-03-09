import ciphers.common

default_key = (20, 19, 18, 17)

def rotkn(inner_ciphertext):

    def get_key():
        yield default_key

        N = ciphers.common.length

        for k in range(N-3):
            yield (k+3, k+2, k+1, k)

        for k in range(N-3):
            yield (k, k+1, k+2, k+3)

        for k0 in range(N):
            for k1 in range(N):
                for k2 in range(N):
                    for k3 in range(N):
                        yield (k0, k1, k2, k3)

    for k0,k1,k2,k3 in get_key():
        rotated = ciphers.common.rot(inner_ciphertext, k0, k1, k2, k3)
        if ciphers.common.makes_sense(rotated):
            print("--------------------- Used (%d %d %d %d) offsets" % (k0, k1, k2, k3))
            return rotated
    
    return None