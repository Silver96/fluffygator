from crypt import crypt
import pickle
import os
# PWLEN = 6

def gen_pairs_from_passwds(filename):
    pairs = set()
    with open(filename, "rt") as file:

        for line in file.readlines():
            line = line.strip(' \n')

            line_pairs = [line[i:i+2] for i in range(0, len(line), 2)]

            for pair in line_pairs:
                if pair not in pairs:
                    pairs.add(pair)

    return pairs



class PasswdCracker:

    def __init__(self, pair_dict_file='pairs.pickle'): ## TODO change this file
        
        self.pairs_filename = os.path.abspath(os.path.join(os.path.dirname(__file__), pair_dict_file))
        
        print('loading pairs from %s' % self.pairs_filename)
        self.load_pairs()


    # TODO variable password length?
    def all_passwds(self):
        pair_list = list(self.pairs)
        for a in pair_list:
            for b in pair_list:
                for c in pair_list:
                    yield a+b+c
        for a in pair_list:
            for b in pair_list:
                for c in pair_list:
                    for d in pair_list:
                        yield a+b+c+d


    def crack(self, crypted_pw):
        salt = crypted_pw[:2]

        for pw in self.all_passwds():
            crypted = crypt(pw, salt)
            if crypted == crypted_pw:
                return pw
        return None


    def append_to_dictionary(self, passwd):
        if len(passwd) % 2 == 1:
            print("-"*15 + "WARNING passwd of odd length \"%s\"" % passwd)

        for i in range(0, len(passwd), 2):
            pair = passwd[i:i+2]
            self.pairs.add(pair)

        self.dump_pairs()


    def reload_dictionary(self):
        self.load_pairs()


    def dump_pairs(self):
        with open(self.pairs_filename, "wb") as file:
            pickle.dump(self.pairs, file)

    def load_pairs(self):
        with open(self.pairs_filename, "rb") as file:
            self.pairs = pickle.load(file)



    