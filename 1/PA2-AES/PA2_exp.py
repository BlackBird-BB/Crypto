import re
from pwn import *
# context(log_level='debug')

s = None

# Packet Structure: < num_blocks(1) || ciphertext(16*num_blocks) || null-terminator(1) >
def Oracle_Send(ctext, num_blocks):
    global s
    while(not s.connected):
        s = remote('128.8.130.16', 49101)

    msg = ctext[:]
    msg.insert(0, num_blocks)
    msg.append(0)
    print(msg)
    msg = bytearray(msg)
    s.send(msg)
    recvbit = s.recv(2)
    try:
        s.close()
    except:
        pass
    return recvbit[0]-ord('0')

if __name__=='__main__':
    s = remote('128.8.130.16', 49101)
    C = '9F0B13944841A832B2421B9EAF6D9836813EC9D944A5C8347A7CA69AA34D8DC0DF70E343C4000A2AE35874CE75E64C31'
    BLOCK = 2
    div = len(C) / (BLOCK + 1)
    # C = re.findall('.{' + str(div) + '}', C)
    C = ['9F0B13944841A832B2421B9EAF6D9836', '813EC9D944A5C8347A7CA69AA34D8DC0', 'DF70E343C4000A2AE35874CE75E64C31']

    M = []
    IVALUE = []
    for b in range(BLOCK): 
        print ('[*] Detecting Block',b+1)
        IV = C[b]
        Ivalue = []
        iv = '00000000000000000000000000000000' 
        iv = re.findall('.{2}', iv)[::-1]
        padding = 1

        for l in range(16):
            print ("  [+] Detecting IVALUE's last", l + 1 , 'block')
            for ll in range(l):
                iv[ll] = hex(int(Ivalue[ll], 16) ^ padding)[2:].zfill(2)

            for n in range(256): #遍历 0x00-0xFF
                iv[l] = hex(n)[2:].zfill(2)
                data = ''.join(iv[::-1]) + C[b + 1]
                
                ctext = [(int(data[i:i + 2], 16)) for i in range(0, len(data), 2)]
                rc = Oracle_Send(ctext, 2)
                
                if str(rc) == '1': 
                    input()
                    Ivalue += [hex(n ^ padding)[2:].zfill(2)]
                    break

            print ('    [-]', ''.join(iv[::-1]))
            print ('    [-]', ''.join(Ivalue[::-1]))
            
            padding += 1

        Ivalue = ''.join(Ivalue[::-1])
        IVALUE += [Ivalue]

        
        m = re.findall('[0-9a-f]+', str(hex(int(IV, 16) ^ int(''.join(Ivalue), 16))))[1].decode('hex')
        M += [m]

        print ('[#] Detecting Block', b + 1 ,'-- Done!')
        print ('[#]', 'The IValue' + str(b + 1), 'is:', Ivalue)
        print ('[#]', 'The M' + str(b + 1) , 'is:', m)
        print ('-' * 50)
        

    print ('[!] The Intermediary Value is:', ''.join(IVALUE))
    print ('[!] The M is:', ''.join(M))

'''
blackbird@HonjouNia /m/d/学/大/现/PA2-AES [1]> python2 ./PA2_exp.py
Connected to server successfully.
[*] Detecting Block 1
  [+] Detecting IVALUE's last 1 block
    [-] 00000000000000000000000000000017
    [-] 16
  [+] Detecting IVALUE's last 2 block
    [-] 0000000000000000000000000000f414
    [-] f616
  [+] Detecting IVALUE's last 3 block
    [-] 000000000000000000000000000ff515
    [-] 0cf616
  [+] Detecting IVALUE's last 4 block
    [-] 0000000000000000000000008b08f212
    [-] 8f0cf616
  [+] Detecting IVALUE's last 5 block
    [-] 0000000000000000000000ef8a09f313
    [-] ea8f0cf616
  [+] Detecting IVALUE's last 6 block
    [-] 0000000000000000000078ec890af010
    [-] 7eea8f0cf616
  [+] Detecting IVALUE's last 7 block
    [-] 0000000000000000002279ed880bf111
    [-] 257eea8f0cf616
  [+] Detecting IVALUE's last 8 block
    [-] 00000000000000009a2d76e28704fe1e
    [-] 92257eea8f0cf616
  [+] Detecting IVALUE's last 9 block
    [-] 000000000000004e9b2c77e38605ff1f
    [-] 4792257eea8f0cf616
  [+] Detecting IVALUE's last 10 block
    [-] 000000000000cd4d982f74e08506fc1c
    [-] c74792257eea8f0cf616
  [+] Detecting IVALUE's last 11 block
    [-] 000000000013cc4c992e75e18407fd1d
    [-] 18c74792257eea8f0cf616
  [+] Detecting IVALUE's last 12 block
    [-] 000000006414cb4b9e2972e68300fa1a
    [-] 6818c74792257eea8f0cf616
  [+] Detecting IVALUE's last 13 block
    [-] 000000b86515ca4a9f2873e78201fb1b
    [-] b56818c74792257eea8f0cf616
  [+] Detecting IVALUE's last 14 block
    [-] 000064bb6616c9499c2b70e48102f818
    [-] 6ab56818c74792257eea8f0cf616
  [+] Detecting IVALUE's last 15 block
    [-] 006565ba6717c8489d2a71e58003f919d
    [-] 6a6ab56818c74792257eea8f0cf616
  [+] Detecting IVALUE's last 16 block
    [-] d67a7aa57808d75782356efa9f1ce606
    [-] c66a6ab56818c74792257eea8f0cf616
[#] Detecting Block 1 -- Done!
[#] The IValue1 is: c66a6ab56818c74792257eea8f0cf616
[#] The M1 is: Yay! You get an
--------------------------------------------------
[*] Detecting Block 2
  [+] Detecting IVALUE's last 1 block
    [-] 000000000000000000000000000000ca
    [-] cb
  [+] Detecting IVALUE's last 2 block
    [-] 000000000000000000000000000084c9
    [-] 86cb
  [+] Detecting IVALUE's last 3 block
    [-] 000000000000000000000000004585c8
    [-] 4686cb
  [+] Detecting IVALUE's last 4 block
    [-] 000000000000000000000000ac4282cf
    [-] a84686cb
  [+] Detecting IVALUE's last 5 block
    [-] 000000000000000000000094ad4383ce
    [-] 91a84686cb
  [+] Detecting IVALUE's last 6 block
    [-] 00000000000000000000ab97ae4080cd
    [-] ad91a84686cb
  [+] Detecting IVALUE's last 7 block
    [-] 00000000000000000070aa96af4181cc
    [-] 77ad91a84686cb
  [+] Detecting IVALUE's last 8 block
    [-] 0000000000000000797fa599a04e8ec3
    [-] 7177ad91a84686cb
  [+] Detecting IVALUE's last 9 block
    [-] 0000000000000036787ea498a14f8fc2
    [-] 3f7177ad91a84686cb
  [+] Detecting IVALUE's last 10 block
    [-] 000000000000c9357b7da79ba24c8cc1
    [-] c33f7177ad91a84686cb
  [+] Detecting IVALUE's last 11 block
    [-] 0000000000a5c8347a7ca69aa34d8dc0
    [-] aec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 12 block
    [-] 0000000061a2cf337d7ba19da44a8ac7
    [-] 6daec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 13 block
    [-] 000000e960a3ce327c7aa09ca54b8bc6
    [-] e46daec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 14 block
    [-] 0000e7ea63a0cd317f79a39fa64888c5
    [-] e9e46daec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 15 block
    [-] 001fe6eb62a1cc307e78a29ea74989c4
    [-] 10e9e46daec33f7177ad91a84686cb
  [+] Detecting IVALUE's last 16 block
    [-] d000f9f47dbed32f6167bd81b85696db
    [-] c010e9e46daec33f7177ad91a84686cb
[#] Detecting Block 2 -- Done!
[#] The IValue2 is: c010e9e46daec33f7177ad91a84686cb
[#] The M2 is: A. =)











--------------------------------------------------
Connection closed successfully.
[!] The Intermediary Value is: c66a6ab56818c74792257eea8f0cf616c010e9e46daec33f7177ad91a84686cb
[!] The M is: Yay! You get an A. =)
'''