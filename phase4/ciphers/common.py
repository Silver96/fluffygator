from string import ascii_lowercase, ascii_uppercase

length = len(ascii_lowercase)

# Dictionary filename for "meaningfulness" check
dictionary_filename = 'ciphers/english_dictionary.txt'


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


def load_dict():
    with open(dictionary_filename, 'rt') as d:
        words = [line.lower().strip('\n ') for line in d.readlines()[1:]] ## discard first line comment
        return set(words)

dictionary = load_dict()


def makes_sense(msg):
    words = msg.lower().replace('\n', ' ').split(' ')
    words = [word.strip('\n ') for word in words]
    words = [word for word in words if len(word) > 0]
    
    # If more than a half words in the message are not present
    # in the dictionary the message does not make sense
    bullshit_threshold = len(words) * 0.5

    count_bullshit = 0

    # bullshits = []
    for word in words:
        if word not in dictionary:
            count_bullshit += 1
            # bullshits.append(word)

    print('count_bullshit', count_bullshit)
    print('bullshit_threshold', bullshit_threshold)

    return count_bullshit < bullshit_threshold
    # if result:
    #     print(bullshits)
    #     import time
    #     time.sleep(10)
    # return result

