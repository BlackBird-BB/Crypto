from Crypto.Cipher import AES
from Crypto import Random
import re
prepend = b"comment1=cooking%20MCs;userdata="
append = b";comment2=%20like%20a%20pound%20of%20bacon"  # len==42


def pad(value, size):
    if len(value) % size == 0:
        return value
    padding = size - len(value) % size
    padValue = bytes([padding]) * padding
    return value + padValue


# this is the dictionary for replacements
QUOTE = {b';': b'%3B', b'=': b'%3D'}

KEY = Random.new().read(AES.block_size)
IV = bytes(AES.block_size)  # for simplicity just a bunch of 0's


def cbc_encrypt(input_text):
    for key in QUOTE:
        input_text = re.sub(key, QUOTE[key], input_text)

    plaintext = prepend + input_text + append
    plaintext = pad(plaintext, AES.block_size)

    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext


def check(ciphertext):
   
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = cipher.decrypt(ciphertext)
    print(f"Plaintext: { plaintext }")

    if b";admin=true;" in plaintext:
        return True

    return False

def test():
    # send two blocks of just A's
    input_string = b'A' * AES.block_size + b'B' * AES.block_size
    ciphertext = cbc_encrypt(input_string)
    print(len(ciphertext))  # 112
    # replace first block of A's with the `required` plain-text
    required = pad(b";admin=true;", AES.block_size)
    # xor each byte of the required with each byte of second block i.e, with 'A'
    inject = bytes([r ^ ord('B') for r in required])  # one block of input
    print(len(inject))  # 16
    # extra = length of ciphertext - length of injected text - length of prefix
    # = one block of input + suffix
    extra = len(ciphertext) - len(inject) - len(prepend)
    # print(extra)
    # keep `inject` fill either side with 0's to match length with original ciphertext
    # xor with 0 does not change value
    # this replaces the first block of input with `required` while the rest is unchanged
    # 0*len(prefix)+infect(A^AES(A)^target)+0*len(suffix+padding)
    inject = bytes(2 * AES.block_size) + inject + bytes(extra)

    # to craft cipher-text, xor the `inject` bytes with
    # corresponding byte of the ciphertext
    crafted = bytes([x ^ y for x, y in zip(ciphertext, inject)])

    if check(crafted):
        print("Admin Found")
    else:
        print("Admin Not Found")
if __name__ == "__main__":
    test()
