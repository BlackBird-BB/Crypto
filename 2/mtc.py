from base64 import b64decode
from hashlib import sha1
from Crypto.Cipher import AES


def correct(x):
    k = []
    a = bin(int(x, 16))[2:]
    for i in range(0, len(a), 8):
        if a[i:i+7].count("1") % 2 == 0:
            k.append(a[i:i+7])
            k.append('1')
        else:
            k.append(a[i:i+7])
            k.append('0')
    return hex(int(''.join(k), 2))[2:]


if __name__ == "__main__":
    passport = '12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4'
    apart = passport[21:27]
    bpart = [7, 3, 1]
    res = 0

    for i in range(len(apart)):
        res = (res + int(apart[i]) * bpart[i % 3]) % 10

    passport = passport[:27] + str(res) + passport[28:]
    mrz = passport[:10] + passport[13:20] + passport[21:28]

    keyseed = sha1(mrz.encode()).hexdigest()[:32] + '00000001'
    tmpkey = sha1(bytes.fromhex(keyseed)).hexdigest()[:32]

    key = bytes.fromhex(correct(tmpkey[:16])+correct(tmpkey[16:]))
    print("GET real key:", key)
    aes = AES.new(key, mode=AES.MODE_CBC, iv=b'\x00'*16)
    cipher = b64decode(
        b'9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI')

    print("PLAINTEXT is:", aes.decrypt(cipher))
