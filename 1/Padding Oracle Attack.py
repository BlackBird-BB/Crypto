from pwn import *
import time
# context.log_level='debug'
s = None

def log(pre, content, level=0):
    if level==0:
        print(f"{pre}[*] {content}")    
    elif level==1:
        print(f"{pre}\033[1;32m[√] {content}\033[0m")
    elif level==2:
        print(f"{pre}\033[1;33m[!] {content}\033[0m")
    else:
        print(f"{pre}\033[1;31m[x] {content}\033[0m")
    
def ValidTest(iv:bytes, cipher:bytes):
    connect()
    msg = b'\x02'+iv+cipher+b'\x00'
    s.send(msg)
    try:
        rep = s.recv(timeout=1)
        return rep[0]-ord('0')
    except:
        log("", "Connect Error.", 3)
        log("", "Retrying... ...", 2)
        ValidTest(iv, cipher)

def connect():
    global s
    if s==None:
        s = remote('128.8.130.16', 49101)
    while(not s.connected()):
        s = remote('128.8.130.16', 49101)

if __name__=='__main__':
    st = time.time()
    log("", "Padding Oracle Attack")
     
    CipherText = bytes.fromhex('9F0B13944841A832B2421B9EAF6D9836813EC9D944A5C8347A7CA69AA34D8DC0DF70E343C4000A2AE35874CE75E64C31')
    # with open("./POA_ciphertext.txt", 'r') as f:
    #     CipherText = f.read()
    BlockNum = len(CipherText)//16
    CipherTextBlocks = [CipherText[i*16:(i+1)*16] for i in range(BlockNum)]
    PlainText = ""

    log("", f"CipherText: {CipherText}")
    log("", f"BlockNumber: {BlockNum}")
    log("", f"Establish Connection with Sever: ")
    connect()   
    log("", f"Start Attacking... ...")

    for bn in range(BlockNum-1):
        log("", f"----------------------- Attacking {bn+1} Block -----------------------")
        IV = CipherTextBlocks[bn]
        EncrypedText = b""
        iv = [b"\x00" for i in range(16)]
        cipher = CipherTextBlocks[bn+1]
        log("   ", f"Block IV: {IV}")
        log("   ", f"Block CipherText: {cipher}")
        for perByteIndex in range(len(iv)):
            log("       ", f"Bruting {perByteIndex+1}_th")
            for bruteValue in range(256):
                for _ in range(perByteIndex):
                    iv[len(iv)-_-1] = ((perByteIndex+1)^EncrypedText[_]).to_bytes(length=1, byteorder='little')

                iv[len(iv)-perByteIndex-1] = bruteValue.to_bytes(length=1, byteorder='little')
                returnValue = ValidTest(b"".join(iv), cipher)
                if returnValue == 1:
                    break
            EncrypedText = EncrypedText + ((perByteIndex+1)^int.from_bytes(iv[len(iv)-perByteIndex-1], byteorder='little')).to_bytes(length=1, byteorder='little')
            log("       ", f"Succeed IV: {b''.join(iv)}", 1)
            log("       ", f"EncrypedText: {EncrypedText[::-1]}", 1)
        BlockPlainText = "".join([chr(EncrypedText[i]^IV[i]) for i in range(16)])
        log("   ", f"BlockPlainText: {BlockPlainText}", 1)
        log("   ", f"PlainText: {PlainText}", 1)
        PlainText = PlainText + BlockPlainText
    ed = time.time()
    log("", f"Done in {ed-st} s", 1)
    log("", f"PlainText: {PlainText}", 1)



#https://www.tr0y.wang/2017/10/06/Crypto1/