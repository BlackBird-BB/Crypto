import base64
import string
import base64

key_table = string.ascii_lowercase+string.ascii_uppercase+string.digits+  "-,. '?!\n"  
MAXLENGTH = 42
solve_cnt = 0

def decrypt(key, cipher):
    global solve_cnt
    solve_cnt = solve_cnt + 1 
    print(f"SOLVE_CNT {solve_cnt}:\n  KEY Length: {len(key)}\n  KEY: {key}\n  Plaintext: ")
    for i in range(len(cipher)):
        print(chr(cipher[i]^key[i%len(key)]), end='')
    print()
    input()

def brute(key_ori, max_length, cipher):
    key = list(key_ori)
    if len(key)==max_length:
        decrypt(key, cipher)
        return
    elif len(key)>max_length:
        return
    for i in range(256):
        flag = True
        for j in range(len(key), len(cipher), max_length):
            if chr(i^cipher[j]) not in key_table:
                flag=False
                break
        if flag:
            key.append(i)
            brute(tuple(key), max_length, cipher)
            key = key[:-1]

if __name__=="__main__":
    with open('Break repeating-key XOR Cipher.txt') as of:
        cipher = of.read()
        cipher = base64.b64decode(cipher)
    for length in range(1, MAXLENGTH):
        brute((), length, cipher)