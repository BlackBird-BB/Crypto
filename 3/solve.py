from Crypto.Util import number as CryptoNumber
import os
from gmpy2 import *
from functools import reduce
os.chdir(os.path.dirname(__file__))


class RSA():

    def __init__(self):
        self.n = []
        self.e = []
        self.c = []
        self.m = {}
        self.solved = []
        frames = ['./data/2/Frame' + str(i) for i in range(21)]
        for i in range(21):
            f = open(frames[i], 'r')
            data = f.read()
            self.n.append(int(data[:256], 16))
            self.e.append(int(data[256:512], 16))
            self.c.append(int(data[512:], 16))

    def Pollard_p_1(self, N):
        """
        Pollard p-1 算法
        :param N:   大整数N
        :return:    因子 P Q
        """
        a = 2
        f = a
        while 1:
            for n in range(1, 200000):
                f = gmpy2.powmod(f, n, N)
                if is_prime(n):
                    d = gcd(f - 1, N)
                    if 1 < d < N:
                        return d, N // d
                    elif d >= N:
                        f = next_prime(a)
                        break
            else:
                break

    def recover_m(self, c):
        """

        :param c:
        :return:
        """
        tmp = hex(c)[2:]
        if tmp[:16] != '9876543210abcdef':
            return 0
        number = int(tmp[16:24], 16)
        plain = CryptoNumber.long_to_bytes(int(tmp[-16:], 16))
        self.m[number] = plain
        return 1

    def decrypt(self, p, q, e, c):
        phi = (p - 1) * (q - 1)
        d = gmpy2.invert(e, phi)
        m = gmpy2.powmod(c, d, p * q)
        return self.recover_m(m)

    def factor_attack(self):
        """
        大因数分解攻击:对每个帧都进行pollard p-1分解
        """
        print(f"[+] Pollard p-1 分解")
        num = ""
        for i in range(21):
            if i not in self.solved:
                tmp = self.Pollard_p_1(self.n[i])
                if isinstance(tmp, tuple):
                    p, q = tmp
                    if self.decrypt(p, q, self.e[i], self.c[i]):
                        self.solved.append(i)
                        num += str(i) + " "
        print(f"[+] 经Pollard p-1破解的帧数为{num}")

    def CRT(self, mi, ai):
        """
        中国剩余定理
        :param mi:  模数
        :param ai:  余数
        :return:    M
        """
        M = reduce(lambda x, y: x * y, mi)
        ai_ti_Mi = [a * (M // m) * gmpy2.invert(M // m, m) for (m, a) in zip(mi, ai)]
        return reduce(lambda x, y: x + y, ai_ti_Mi) % M

    def small_e_boardcast_attack(self, nlist, e, clist):
        m = self.CRT(nlist, clist)
        tmp = iroot(m, e)
        if tmp[1] == 1:
            return tmp[0]
        else:
            return 0

    def low_encryption_exponent3_attack(self):
        print(f"[+] 低加密指数3")
        e = 3
        nums = [7, 11, 15]
        nlist = [self.n[i] for i in nums]
        clist = [self.c[i] for i in nums]
        num = ""
        m = self.small_e_boardcast_attack(nlist, e, clist)
        if self.recover_m(m):
            for i in nums:
                self.solved.append(i)
                num += str(i) + " "
        print(f"[+] 根据低加密指数破解的帧数为{num}")

    def low_encryption_exponent5_attack(self):
        print(f"[+] 低加密指数5")
        e = 5
        nums = [3, 8, 12, 16, 20]
        nlist = [self.n[i] for i in nums]
        clist = [self.c[i] for i in nums]
        num = ""
        m = self.small_e_boardcast_attack(nlist, e, clist)
        if self.recover_m(m):
            for i in nums:
                self.solved.append(i)
                num += str(i) + " "
        print(f"[+] 根据低加密指数破解的帧数为{num}")

    def same_module_attack(self):
        print(f"[+] 共模攻击")
        N = self.n[0]
        e1 = self.e[0]
        e2 = self.e[4]
        c1 = self.c[0]
        c2 = self.c[4]
        d1 = gmpy2.invert(e1, e2)
        d2 = (d1 * e1 - 1) // e2
        true_c2 = gmpy2.invert(c2, N)
        m = (gmpy2.powmod(c1, d1, N) * gmpy2.powmod(true_c2, d2, N)) % N
        self.recover_m(m)
        print(f"[+] 根据低加密指数破解的帧数为 0 4")

    def fermat(self, N):
        a = isqrt(N)
        b2 = a * a - N
        b = isqrt(N)
        count = 0
        while b * b != b2:
            a = a + 1
            b2 = a * a - N
            b = isqrt(b2)
            count += 1
        p = a + b
        q = a - b
        assert N == p * q
        return p, q

    def fermat_attack(self):
        print(f"[+] Fermat 素性分解")
        N = self.n[10]
        tmp = self.fermat(N)
        if isinstance(tmp, tuple):
            p, q = tmp
            m = self.decrypt(p, q, self.e[10], self.c[10])
            self.recover_m(m)

        print(f"[+] Fermat 素性分解的帧为 10")

    def show(self):
        print(f"[+]经过破解的部分密文为：")
        for i in range(21):
            print(f"{i}:\t{self.m.get(i)}")

    def factor_collision(self):
        print(f"[+] 因数碰撞")
        p = gcd(self.n[1], self.n[18])
        q1 = self.n[1]//p
        q2 = self.n[18]//p
        self.recover_m(self.decrypt(p, q1, self.e[1], self.c[1]))
        self.recover_m(self.decrypt(p, q2, self.e[18], self.c[18]))
        print(f"[+] 因数碰撞后破解的帧为 1 18")

    def attack(self):
        self.factor_attack()
        self.low_encryption_exponent3_attack()
        self.low_encryption_exponent5_attack()
        self.same_module_attack()
        self.fermat_attack()
        self.factor_collision()
        self.show()


if __name__ == '__main__':
    rsa = RSA()
    rsa.attack()
