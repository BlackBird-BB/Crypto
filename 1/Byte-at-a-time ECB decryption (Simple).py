from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import AES

UNKNOWN_STRING = b"""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = Random.new().read(16)

def log(pre, content, level=0):
    if level==0:
        print(f"{pre}[*] {content}")    
    elif level==1:
        print(f"{pre}\033[1;32m[√] {content}\033[0m")
    elif level==2:
        print(f"{pre}\033[1;33m[!] {content}\033[0m")
    else:
        print(f"{pre}\033[1;31m[x] {content}\033[0m")

def pad(your_string, msg):
 
    paddedMsg = your_string + msg

    size = 16
    length = len(paddedMsg)
    if length % size == 0:
        return paddedMsg

    padding = size - (length % size)
    padValue = bytes([padding])
    paddedMsg += padValue * padding

    return paddedMsg


def encryption_oracle(your_string):
   
   # msg = bytes('The unknown string given to you was:\n', 'ascii')
    # append the `UNKNOWN_STRING` given to us to the `msg`
    #plaintext = msg + b64decode(UNKNOWN_STRING)
    plaintext = b64decode(UNKNOWN_STRING)
    # add `your_string` to prepend to `plaintext` and apply `PKCS#7` padding to correct size
    paddedPlaintext = pad(your_string, plaintext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    ciphertext = cipher.encrypt(paddedPlaintext)

    return ciphertext


def detect_block_size():
    ori_length = len(encryption_oracle(b""))
    for i in range(1, 256):
        length = len(encryption_oracle(b"a"*i))
        if length!=ori_length:
            return length - ori_length
     
def detect_mode(blocksize):
    blockcipher1 = encryption_oracle(b"")[-1*blocksize:]
    blockcipher2 = encryption_oracle(b"a"*blocksize)[-1*blocksize:]
    return blockcipher1 == blockcipher2

def list2bytes(tmp:list):
    return b"".join([int.to_bytes(i, length=1, byteorder='little') for i in tmp])

def int2byte(tmp:int):
    return int.to_bytes(tmp, length=1, byteorder='little')

def ecb_decrypt(block_size):
    log("", "Start Attacking... ...")
    PlainText = []
    while(True):
        log("   ", f"Attacking {len(PlainText)+1}_th Byte:")
        tables = {}
        bruteInput = (b"A"*block_size+list2bytes(PlainText))[-1*block_size+1:]
        log("   ", f"BruteInput: {bruteInput}+BruteValue")
        log("   ", f"Generating Tables... ...")
        for bruteValue in range(256):
            key = encryption_oracle(bruteInput+int2byte(bruteValue))[:block_size]
            tables[key] = bruteValue
        log("   ", f"Tables Generating Done.")
        inp = b"A"*((block_size-1-len(PlainText))%block_size)
        log("   ", f"InputValue: {inp}")
        key = encryption_oracle(inp)[(len(PlainText)//block_size)*block_size:][:16]
        log("   ", f"UniqueKey: {key}")
        try:
            PlainText.append(tables[key])
            log("   ", f"Find Value: {chr(tables[key])}")
            log("   ", f"All PlainText: {PlainText}")
        except:
            log("   ", f"Attacking Over: Complete or ERROR.", 3)
            return PlainText
        print()

def main():
    # detect block size
    print(f"1. A server: Input UserInput, Output Encrypt(UserInput + UnKnownString).\n2. Every time use the SAME KEY.\n3. UnknownString in unchanged.\nWhat's UnkonwnString?\n")
    block_size = detect_block_size()
    log("", f"Block Size: { block_size }")

    # detect the mode (should be ECB)
    if detect_mode(block_size):
        log("", "Encrypt Mode: ECB")
    else:
        log("", "Encrypt Mode: NOT ECB")
    PlainText = ecb_decrypt(block_size)
    print("", f"PlainText: {''.join([chr(i) for i in PlainText])}", 1)


if __name__ == "__main__":
    main()
