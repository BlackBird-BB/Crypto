import re
from gmpy2 import *
import time
import os
os.chdir(os.path.dirname(__file__))

Data = []
for i in range(21):
    with open('./data/2/Frame'+str(i)) as fp:
        data = re.findall('(.{256})(.{256})(.{256})',
                          fp.read().replace('\n', ''))
        Data += data

N = [int(n, 16) for n, e, c in Data if int(e, 16)]
C = [int(c, 16) for n, e, c in Data if int(e, 16)]
E = [int(e, 16) for n, e, c in Data if int(e, 16)]


with open('pq.txt', 'r') as fp:
    data = fp.read()
    p = [int(i) for i in re.findall(r'p=([0-9]+)', data)]
    q = [int(i) for i in re.findall(r'q=([0-9]+)', data)]
    pq = zip(p, q)

cN = [i*j for i, j in pq]
if [i for i in range(21) if cN[i] != N[i]]:
    print('[!!!]You are wrong!!')
    kill
else:
    print('[!]Well done in pq')

print('[+]Hacking Frame...')

print('  [-]Calculating Phi...',)
Phi = [(i-1)*(j-1) for i, j in pq]
print('Done!')

print('  [-]Calculating d...',)
D = [invert(E[i], Phi[i]) for i in range(21)]
print('Done!')

print('  [-]Hacking m...',)
M = [('%x' % pow(C[i], D[i], N[i])) for i in range(21)]
print('Done!')

print('[+]All data is:')
for i, m in enumerate(M):
    print('  [-]Frame%d' % i)
    print('    [-]p:', '%x' % p[i])
    print('    [-]q:', '%x' % q[i])
    print('    [-]n:', '%x' % N[i])
    print('    [-]f:', '%x' % Phi[i])
    print('    [-]e:', '%x' % E[i])
    print('    [-]d:', '%x' % D[i])
    print('    [-]m:', m)
    print('    [-]c:', '%x' % C[i])

print('[!]The Password is:', ''.join([m.decode('hex')[-8:] for m in sorted(set(M))]))
