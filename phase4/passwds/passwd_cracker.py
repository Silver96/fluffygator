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

def open_listen_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    return sock, sock.getsockname() ## return the (ip, port)


def send_crack_passwd_req(crypted_passwd, port):    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        while sock.connect_ex(('128.114.59.42', 2001)) != 0:
            sleep(1)

        req = "%s 128.114.59.29 %d" % (crypted_passwd, port)
        
        reply = None
        while not reply == 'OK':
            sock.send(req.encode())
            reply = sock.recv(10).decode().strip('\n')
            sleep(2)

def crack_passwd_nsa(crypted_passwd):

    def print_time():
        now = datetime.now().time()
        print("\n------ %d:%d:%d" % (now.hour, now.minute, now.second))

    listen_sock, (ip, port) = open_listen_socket(0)

    print_time()
    send_crack_passwd_req(crypted_passwd, port)
    
    sock, _ = listen_sock.accept()
    
    reply = sock.recv(100).decode()
    _, passwd = reply.strip(' \n').split(" ")

    listen_sock.close()
    sock.close()
    return passwd

class PasswdCracker:

    def __init__(self, pair_dict_file='pairs.pickle'):
        
        self.pairs_filename = os.path.abspath(os.path.join(os.path.dirname(__file__), pair_dict_file))
        self.gen_passwds_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), 'generated_passwds/'))
        
        # print('loading pairs from %s' % self.pairs_filename)
        self.load_pairs()


    # TODO variable password length?
    def all_passwds(self):
        pair_list = [p for p in sorted(self.pairs)]
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

        ## Generated password
        if salt in ['ar','ep','it','pa','ss','to']:
            all_passwds_gen = self.all_passwds()
            
            N_MAX = 8000000
            N = 0
            filename = self.gen_passwds_folder + '/' + salt + '0'
            with open(filename, 'rt') as f:
                for pw in all_passwds_gen:
                    N += 1
                    if N == N_MAX:
                        break
                    crypted = f.readline().strip(' \n')
                    if crypted == crypted_pw:
                        return pw

            filename = self.gen_passwds_folder + '/' + salt + '1'
            with open(filename, 'rt') as f:
                for pw in all_passwds_gen:
                    crypted = f.readline().strip(' \n')
                    if crypted == crypted_pw:
                        return pw


        for pw in self.all_passwds():
            crypted = crypt(pw, salt)
            if crypted == crypted_pw:
                return pw

        return None

    def crack_nsa(self, crypted_pw):
        return crack_passwd_nsa(crypted_pw)

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

