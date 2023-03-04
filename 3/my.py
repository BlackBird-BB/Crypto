import requests
from Crypto.Util import number as CryptoNumber
import os
import gmpy2
from functools import reduce
import string
import time
from multiprocessing.context import Process

os.chdir(os.path.dirname(__file__))
       
class RSACracker():
    
    class Attack():
        '''
        Attack类为该RSACracker的破解模块
        包含以下攻击方式：
         - 共模攻击
         - 直接分解（费马，Pollard_p_1）
         - 低加密指数攻击
         - 低加密指数广播攻击
         - 维纳攻击
         - 因子碰撞攻击
        可以自行添加扩展攻击方式，但注意命名规范"def example_attack():"
        '''
        def __init__(self, outer) -> None:
            self.outer = outer
            self.attacks = [getattr(self, func_name) for func_name in dir(self) if "attack" in func_name]
            for at in self.attacks:
                at()
                             
        def DirectDecomposition_attack(self):
            def Pollard_p_1(N):
                """
                Pollard p-1 算法
                :param N:   大整数N
                :return:    因子 P Q
                """
                a = 2
                f = a
                while 1:
                    for n in range(1, 200000):
                        f =  gmpy2.powmod(f, n, N)
                        if  gmpy2.is_prime(n):
                            d =  gmpy2.gcd(f - 1, N)
                            if 1 < d < N:
                                return d, N // d
                            elif d >= N:
                                f =  gmpy2.next_prime(a)
                                break
                    else:
                        break
            
            def fermat_attack():
                self.outer.utils.log(f"Fermat 素性分解")
                N = self.outer.n[10]
                tmp = self.outer.utils.fermat(N)
                if isinstance(tmp, tuple):
                    p, q = tmp
                    self.outer.utils.RSA_decrypt(p, q, self.outer.e[10], self.outer.c[10], 10)
            
            def factor_attack():
                """
                大因数分解攻击:对每个帧都进行pollard p-1分解
                """
                self.outer.utils.log(f"Pollard p-1 分解")
                num = ""
                for i in range(21):
                    if i not in self.outer.solved:
                        tmp = Pollard_p_1(self.outer.n[i])
                        if isinstance(tmp, tuple):
                            p, q = tmp
                            if self.outer.utils.RSA_decrypt(p, q, self.outer.e[i], self.outer.c[i], i):
                                self.outer.solved.append(i)
                                num += str(i) + " "
                self.outer.utils.log(f"经Pollard p-1破解的帧数为{num}")
            
            def internetSearch(N):
                pass
                
            fermat_attack()
            factor_attack()
        
        def same_module_attack(self):
            self.outer.utils.log("共模攻击")
            N = self.outer.n[0]
            e1 = self.outer.e[0]
            e2 = self.outer.e[4]
            c1 = self.outer.c[0]
            c2 = self.outer.c[4]
            d1 = gmpy2.invert(e1, e2)
            d2 = (d1 * e1 - 1) // e2
            true_c2 = gmpy2.invert(c2, N)
            m = (gmpy2.powmod(c1, d1, N) * gmpy2.powmod(true_c2, d2, N)) % N
            self.outer.recover_m(m)
            self.outer.utils.log(f"根据低加密指数破解的帧数为 0 4")
            
        def factor_collision_attack(self):
            self.outer.utils.log(f"因数碰撞")
            p = gmpy2.gcd(self.outer.n[1], self.outer.n[18])
            q1 = self.outer.n[1]//p
            q2 = self.outer.n[18]//p
            self.outer.recover_m(self.outer.utils.RSA_decrypt(p, q1, self.outer.e[1], self.outer.c[1], 1))
            self.outer.recover_m(self.outer.utils.RSA_decrypt(p, q2, self.outer.e[18], self.outer.c[18], 18))
            self.outer.utils.log(f"因数碰撞后破解的帧为 1 18")          
        
        def small_e_boardcast(self, nlist, e, clist):
            m = self.outer.utils.CRT(nlist, clist)
            tmp = gmpy2.iroot(m, e)
            if tmp[1] == 1:
                return tmp[0]
            else:
                return 0

        def low_encryption_exponent3_attack(self):
            self.outer.utils.log(f"低加密指数3")
            e = 3
            nums = [7, 11, 15]
            nlist = [self.outer.n[i] for i in nums]
            clist = [self.outer.c[i] for i in nums]
            num = ""
            m = self.small_e_boardcast(nlist, e, clist)
            if self.outer.recover_m(m):
                for i in nums:
                    self.outer.solved.append(i)
                    num += str(i) + " "
            self.outer.utils.log(f"根据低加密指数破解的帧数为{num}")

        def low_encryption_exponent5_attack(self):
            self.outer.utils.log(f"低加密指数5")
            e = 5
            nums = [3, 8, 12, 16, 20]
            nlist = [self.outer.n[i] for i in nums]
            clist = [self.outer.c[i] for i in nums]
            num = ""
            m = self.small_e_boardcast(nlist, e, clist)
            if self.outer.recover_m(m):
                for i in nums:
                    self.outer.solved.append(i)
                    num += str(i) + " "
            self.outer.utils.log(f"根据低加密指数破解的帧数为{num}")
      
        # def wiener_attack(e, n):
        #     def continuedFra(x, y):
        #         # 展开为连分数
        #         cF = []
        #         while y:
        #             cF += [x / y]
        #             x, y = y, x % y
        #         return cF

        #     def Simplify(ctnf):
        #         numerator = 0
        #         denominator = 1
        #         for x in ctnf[::-1]:
        #             numerator, denominator = denominator, x * denominator + numerator
        #         return (numerator, denominator)

        #     def calculateFrac(x, y):
        #         # 连分数化简
        #         cF = continuedFra(x, y)
        #         cF = map(Simplify, (cF[0:i] for i in xrange(1, len(cF))))
        #         return cF

        #     def solve_pq(a, b, c):
        #         # 解韦达定理
        #         par = gmpy2.isqrt(b * b - 4 * a * c)
        #         return (-b + par) / (2 * a), (-b - par) / (2 * a)
            
        #     for (d, k) in calculateFrac(e, n):
        #         if k == 0: continue
        #         if (e * d - 1) % k != 0: 
        #             continue

        #         phi = (e * d - 1) / k
        #         p, q = solve_pq(1, n - phi + 1, n)
        #         if p * q == n:
        #             return abs(int(p)), abs(int(q))
        #         return 

    class Utils():
        '''
        Utils类为该RSACracker的算法模块(与该题目无关代码):
        - RSA Decrypt
        
        '''
        def __init__(self, outer) -> None:
            self.outer = outer

        def RSA_decrypt(self, p, q, e, c, index=None):
            phi = (p - 1) * (q - 1)
            d =  gmpy2.invert(e, phi)
            m =  gmpy2.powmod(c, d, p * q)
            rel = self.outer.recover_m(m)
            if rel and index:
                fp = open("./pq.txt", 'w')
                self.log(f"{index}_th has been attacked.\n  p:{p}\n  q:{q}\n\n\n", 0)
                fp.close()
        
        def CRT(self, mi, ai):
            """
            中国剩余定理
            :param mi:  模数
            :param ai:  余数
            :return:    M
            """
            M = reduce(lambda x, y: x * y, mi)
            ai_ti_Mi = [a * (M // m) *  gmpy2.invert(M // m, m) for (m, a) in zip(mi, ai)]
            return reduce(lambda x, y: x + y, ai_ti_Mi) % M
        
        def fermat(self, N):
            a = gmpy2.isqrt(N)
            b2 = a * a - N
            b = gmpy2.isqrt(N)
            count = 0
            while b * b != b2:
                a = a + 1
                b2 = a * a - N
                b = gmpy2.isqrt(b2)
                count += 1
            p = a + b
            q = a - b
            assert N == p * q
            return p, q        
    
        def log(self, msg, level=0, fp=None):
            '''
            日志方法
            :msg: 输出信息
            :level: 0 normal; 1 warning; 2 critical;
            '''
            if level==0:
                print(f"[+] {msg}", file=fp)
            elif level==1:
                print(f"\033[33m[*] {msg}\033[0m", file=fp)
            elif level==2:
                print(f"\033[31m[x] {msg}\033[0m", file=fp)
        
        def show(self):
            self.log(f"经过破解的部分密文为：")
            for i in range(21):
                print(f"{i}:\t{self.outer.m.get(i)}")
                
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
        
        
        self.utils = self.Utils(self)
        self.attack = self.Attack(self)
        self.utils.show()
    
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
        try:
            for _ in plain:
                if chr(_) not in string.printable:
                    return 0
        except:
            self.utils.log(f"DecodeError: {plain}", 2)
            exit(-1)
        self.m[number] = plain
        return 1

if __name__ == '__main__':
    rsa = RSACracker()