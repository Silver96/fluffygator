from crypt import crypt
from passwd_cracker import PasswdCracker

folder = 'generated_passwds/'
salts  = ['ar','ep','it','pa','ss','to']

cracker = PasswdCracker()

for salt in salts:
    all_passwds_gen = cracker.all_passwds()
    
    N_MAX = 8000000
    N = 0
    with open(folder + salt + '0', 'wt') as file:
        for pw in all_passwds_gen:
            N += 1
            if N == N_MAX:
                break
            crypted = crypt(pw, salt)
            file.write(crypted+'\n')

    with open(folder + salt + '1', 'wt') as file:
        for pw in all_passwds_gen:
            crypted = crypt(pw, salt)
            file.write(crypted+'\n')
