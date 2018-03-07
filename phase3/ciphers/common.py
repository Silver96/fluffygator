from string import ascii_lowercase, ascii_uppercase

length = len(ascii_lowercase)

# Dictionary filename for "meaningfulness" check
dictionary_filename = 'ciphers/english_dictionary.txt'

# Threshold for "meaningfulness" check
sense_threshold = 25

def rot(text, *keys):

    def shift(c, k, alphabet):
        i = alphabet.index(c)
        i = (i + k) % len(alphabet)
        return alphabet[i]

    rotated = []
    i = 0
    for c in text:

        if c in ascii_lowercase:
            rotated.append(shift(c, keys[i%len(keys)], ascii_lowercase))
        elif c in ascii_uppercase:
            rotated.append(shift(c, keys[i%len(keys)], ascii_uppercase))
        else:
            rotated.append(c)
        i += 1

    return "".join(rotated)

def makes_sense(msg):

    def load_dict():

        with open(dictionary_filename, 'rt') as d:
            words = [line.lower()[:-1] for line in d.readlines()[1:]] ## discard first line comment
            return set(words)

    dictionary = load_dict()
    words = msg.lower().split(' ')
    count = 0

    for word in words:
        if word in dictionary:
            count += 1

    return count >= sense_threshold
