import base64


def ciphertext_XOR(s):
    _data = []
    for single_character in range(256):
        ciphertext = Single_XOR(s, single_character)
        # print(ciphertext)
        score = English_Scoring(ciphertext)
        data = {
            'Single character': single_character,
            'ciphertext': ciphertext,
            'score': score
        }
        _data.append(data)
    score = sorted(_data, key=lambda score: score['score'], reverse=True)[0]
    return score


def English_Scoring(t):
    latter_frequency = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .15000
    }
    return sum([latter_frequency.get(chr(i), 0) for i in t.lower()])


def Single_XOR(s, single_character):
    t = b''
    for i in s:
        t = t+bytes([i ^ single_character])
    return t


def Repeating_key_XOR(_message, _key):
    cipher = b''
    length = len(_key)
    for i in range(0, len(_message)):
        cipher = cipher + bytes([_message[i] ^ _key[i % length]])
    return cipher


def hamming_distance(a, b):
    distance = 0
    for i, j in zip(a, b):
        byte = i ^ j
        distance = distance + sum(k == '1' for k in bin(byte))
    return distance


def Get_the_keysize(ciphertext):
    data = []
    for keysize in range(2, 41):
        block = [ciphertext[i:i+keysize]
                 for i in range(0, len(ciphertext), keysize)]
        distances = []
        for i in range(0, len(block), 2):
            try:
                block1 = block[i]
                block2 = block[i+1]
                distance = hamming_distance(block1, block2)
                distances.append(distance / keysize)
            except:
                break
        _distance = sum(distances) / len(distances)
        _data = {
            'keysize': keysize,
            'distance': _distance
        }
        data.append(_data)
    _keysize = sorted(data, key=lambda distance: distance['distance'])[0]
    return _keysize


def Break_repeating_key_XOR(ciphertext):

    # Guess the length of the key
    _keysize = Get_the_keysize(ciphertext)
    keysize = _keysize['keysize']
    print(keysize)
    key = b''
    cipher = b''
    block = [ciphertext[i:i+keysize]
             for i in range(0, len(ciphertext), keysize)]
    for i in range(0, keysize):
        t = b''
        for j in range(0, len(block)-1):
            s = block[j]
            t = t+bytes([s[i]])
        socre = ciphertext_XOR(t)
        key = key + bytes([socre['Single character']])
    for k in range(0, len(block)):
        cipher = cipher+Repeating_key_XOR(block[k], key)
    # print(key)
    return cipher, key


if __name__ == '__main__':
    with open('Break repeating-key XOR Cipher.txt') as of:
        ciphertext = of.read()
        ciphertext = base64.b64decode(ciphertext)
    cipher, key = Break_repeating_key_XOR(ciphertext)
    print("cipher:", cipher, "\nkey:", key)


# Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
# Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
# this is a test
# and
# wokka wokka!!!
# is 37. Make sure your code agrees before you proceed.
# For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
# The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
# Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
# Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
# Solve each block as if it was single-character XOR. You already have code to do this.
# For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

# 猜测密钥长度后，将密文分成相应长度块，计算相邻块间的汉明距离，具有最小归一化汉明距离的块长度很可能是真实密钥长度。

# 用字母频率分析的方法爆破当前位置的密钥