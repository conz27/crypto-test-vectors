from types import *
from random import *
from hashlib import *


#
# Bit operations
#

# bitLen() returns a length of the number in bits
def bitLen(int_type):
    length = 0
    while (int_type):
        int_type >>= 1
        length += 1
    return (length)


# testBit() returns a nonzero result, 2**offset, if the bit at 'offset' is one.
def testBit(int_type, offset):
    mask = 1 << offset
    return (int_type & mask)


# setBit() returns an integer with the bit at 'offset' set to 1.
def setBit(int_type, offset):
    mask = 1 << offset
    return (int_type | mask)


# clearBit() returns an integer with the bit at 'offset' cleared.
def clearBit(int_type, offset):
    mask = ~(1 << offset)
    return (int_type & mask)


# toggleBit() returns an integer with the bit at 'offset' inverted, 0 -> 1 and 1 -> 0.
def toggleBit(int_type, offset):
    mask = 1 << offset
    return (int_type ^ mask)


#
# Inverse and square root functions
#

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    a = a % m
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def pow_mod(x, y, z):
    'Calculate (x ** y) % z efficiently.'
    acc = 1
    while y:
        if y & 1:
            acc = acc * x % z
        y >>= 1
        x = x * x % z
    return acc


def sqrt(a, m):
    return pow_mod(a, (m + 1) / 4, m)


#
# Conversion functions
#

def inthex_to_long(x):
    'Basic function to convert Int or String to Int'
    if type(x) is int or type(x) is int:
        return int(x)
    # StringType is invalid in Python 3
    #elif type(x) is StringType:
    elif isinstance(x, str):
        return int(x, 16)


#
# ECC curve class
#

class ECurve:
    'Common base class for all ECC curves'

    def __init__(self, name, p, a, b, gx, gy, n, h):
        self.name = name
        self.p = inthex_to_long(p)
        self.a = inthex_to_long(a)
        self.b = inthex_to_long(b)
        self.gx = inthex_to_long(gx)
        self.gy = inthex_to_long(gy)
        self.n = inthex_to_long(n)
        self.h = inthex_to_long(h)

    def __cmp__(self, c):
        if (self.p == c.p and
                    self.a == c.a and
                    self.b == c.b and
                    self.gx == c.gx and
                    self.gy == c.gy and
                    self.n == c.n and
                    self.h == c.h):
            return 0
        else:
            return 1

    def __str__(self):
        return self.name

    #


# Curves constant objects
#

'''secp256r1 curve with p=(2**224)*(2**32-1)+2**192+2**96-1
'''
secp256r1 = ECurve(
    "secp256r1",
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",  # p
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",  # a
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",  # b
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",  # gx
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",  # gy
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",  # n
    1  # h
)

'''secp384r1 curve with p=2**384-2**128-2**96+2**32-1
'''
secp384r1 = ECurve(
    "secp384r1",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",  # p
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",  # a
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",  # b
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",  # gx
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",  # gy
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",  # n
    1  # h
)


#
# ECC point class
#

class ECPoint:
    'Common base class for all ECC points (all curves)'
    'Order of passed argument sets by priority:'
    '  0 - ECPoint (nothing else), 1 - ECPointJ (nothing else), 2 - x,y,[curve-optional]'

    def __init__(self, *args, **kwargs):
        if (len(args) == 1):
            if (isinstance(args[0], ECPoint)):
                ec_point = args[0]
                self.ecc = ec_point.ecc
                self.x = ec_point.x % self.ecc.p
                self.y = ec_point.y % self.ecc.p
                # Do not check of point is on the curve when it's point at infinity
                if (not self.is_infinity()):
                    self.is_on_curve()
            elif (isinstance(args[0], ECPointJ)):
                ec_pointj = args[0]
                self.ecc = ec_pointj.ecc
                if (ec_pointj.is_infinity()):
                    self.x = int(0)
                    self.y = int(0)
                else:  # Convert to Affine from Jacobian
                    zinv = modinv(ec_pointj.z, self.ecc.p)
                    self.x = (ec_pointj.x * zinv ** 2) % self.ecc.p
                    self.y = (ec_pointj.y * zinv ** 3) % self.ecc.p
                    self.is_on_curve()
        elif (len(args) == 2 or len(args) == 3):
            # Octet string converion case
            if (isinstance(args[0], ECurve)):
                self.ecc = args[0]
                self.input(args[1])
                return
            if (len(args) == 3):
                self.ecc = args[2]
            else:
                self.ecc = secp256r1  # default curve
            self.x = inthex_to_long(args[0]) % self.ecc.p
            self.y = inthex_to_long(args[1]) % self.ecc.p
            # Do not check of point is on the curve when it's point at infinity
            if (not self.is_infinity()):
                self.is_on_curve()
        else:
            raise Exception("Bad parameters in ECPoint constructor!")

    def __cmp__(self, b):
        if (self.x == b.x and self.y == b.y):
            return 0
        else:
            return 1

    def __neg__(self):
        return ECPoint(self.x, self.ecc.p - self.y, self.ecc)

    def __add__(self, right):
        if right.__class__ == ECPointJ:
            return right.add(self)
        if right.__class__ == ECPoint:
            return self.add(right)
        raise Exception("Operand on the right is not ECPoint/ECPointJ type!")

    def __radd__(self, left):
        self + left  # or self.__add__(left)

    def __sub__(self, right):
        if right.__class__ != ECPoint:
            raise Exception("Operand on the right is not ECPoint type!")
        return self.add(-right)

    def __rmul__(self, left):
        if type(left) not in (int, int):
            raise Exception("Operand on the left is not integer type!")
        #      return self.multiply(left)   # switched to Jacobian version
        return self.multiplyJ(left)

    def __str__(self):
        return "[" + hex(self.x) + "], [" + hex(self.y) + "]"

    def is_on_curve(self):
        'Checking that (x,y) is on the curve: y^2 = x^3 + a*x + b'
        if (not ((self.y ** 2 - self.x ** 3 - self.ecc.a * self.x - self.ecc.b) % self.ecc.p) == 0):
            raise Exception("Point is not on the curve!\n" + str(self))
        return True

    def is_infinity(self):
        'Checking that (x,y) is infinity - (0,0)'
        if (self.x == 0 and self.y == 0):
            return True

    def add(self, b):
        'Point addition: x3 = lmb^2 - x1 - x2,  y3 = lmb * (x2 - x3) - y2'
        '                where lmb = (y2-y1)/(x2-x1)'
        if (self.ecc != b.ecc):
            raise Exception("Different curves for input points! " + str(self.ecc) + ", " + str(b.ecc))
        if (self.is_infinity()):
            return b
        if (b.is_infinity()):
            return self
        self.is_on_curve()
        b.is_on_curve()
        if (self == b):
            return self.double()
        if (self == -b):
            return ECPoint(0, 0, self.ecc)
        lmb = ((b.y - self.y) * modinv(b.x - self.x, self.ecc.p)) % self.ecc.p
        x3 = lmb ** 2 - self.x - b.x
        y3 = lmb * (b.x - x3) - b.y
        return ECPoint(x3, y3, self.ecc)

    def double(self):
        'Point doubling: x3 = t^2 - 2*x,  y3 = t * (x - x3) - y'
        '                where t = (3*x+a)/(2y)'
        if (self.is_infinity()):
            return self
        self.is_on_curve()
        t = ((3 * self.x ** 2 + self.ecc.a) * modinv(2 * self.y, self.ecc.p)) % self.ecc.p
        x3 = t ** 2 - 2 * self.x
        y3 = t * (self.x - x3) - self.y
        return ECPoint(x3, y3, self.ecc)

    def multiply(self, scalar):
        k = inthex_to_long(scalar) % self.ecc.n
        bl = bitLen(k)
        if (bl == 0):
            return ECPoint(0, 0, self.ecc)
        if (bl == 1):
            return self
        acc = self
        for i in reversed(list(range(bl - 1))):
            acc = acc + acc
            if (testBit(k, i) != 0):
                acc = acc + self
        return acc

    def multiplyJ(self, scalar):
        k = inthex_to_long(scalar) % self.ecc.n
        bl = bitLen(k)
        if (bl == 0):
            return ECPoint(0, 0, self.ecc)
        if (bl == 1):
            return self
        acc = ECPointJ(self)
        for i in reversed(list(range(bl - 1))):
            acc = acc.double()
            if (testBit(k, i) != 0):
                acc = acc + self
        return ECPoint(acc)

    def output(self, compress=True):
        'Output with/without point compression'
        self.is_on_curve()
        l = bitLen(self.ecc.p)
        os_len = 2 * ((l - 1) / 8 + 1)
        if (compress):
            if (testBit(self.y, 0) != 0):
                flag = "03"
            else:
                flag = "02"
            return flag + format(self.x, "x").zfill(os_len)
        else:
            return "04" + format(self.x, "x").zfill(os_len) + format(self.y, "x").zfill(os_len)

    def input(self, os):
        'Input octet string and convert to ECPoint'
        l = bitLen(self.ecc.p)
        os_len = 2 * ((l - 1) / 8 + 1)
        # Compressed
        if (os_len == (len(os) - 2)):
            flag = os[0:2]
            if (flag != "02" and flag != "03"):
                raise Exception("Bad octet string flag!")
            self.x = int(os[2:(2 + os_len)], 16)
            self.y = (self.x ** 3 + self.ecc.a * self.x + self.ecc.b) % self.ecc.p
            self.y = sqrt(self.y, self.ecc.p);
            if ((testBit(self.y, 0) != 0 and flag == "02") or (testBit(self.y, 0) == 0 and flag == "03")):
                self.y = self.ecc.p - self.y
            self.is_on_curve()
            return self;

        # Uncompressed
        elif ((2 * os_len) == (len(os) - 2)):
            flag = os[0:2]
            if (flag != "04"):
                raise Exception("Bad octet string flag!")
            self.x = int(os[2:(2 + os_len)], 16)
            self.y = int(os[(2 + os_len):(2 + 2 * os_len)], 16)
            self.is_on_curve()
            return self;

        # Bad length
        else:
            raise Exception("Bad octet string length!")


class ECPointJ:
    'Common base class for all ECC points in Jacobian (all curves)'
    'Order of passed argument sets by priority:'
    '  0 - ECPointJ (nothing else), 1 - ECPoint (nothing else), 2 - x,y,z,[curve-optional]'

    def __init__(self, *args, **kwargs):
        if (len(args) == 1):
            if (isinstance(args[0], ECPointJ)):
                ec_pointj = args[0]
                self.ecc = ec_pointj.ecc
                self.x = ec_pointj.x % self.ecc.p
                self.y = ec_pointj.y % self.ecc.p
                self.z = ec_pointj.z % self.ecc.p
                # Do not check of point is on the curve when it's point at infinity
                if (not self.is_infinity()):
                    self.is_on_curve()
            elif (isinstance(args[0], ECPoint)):
                ec_point = args[0]
                self.ecc = ec_point.ecc
                if (ec_point.is_infinity()):
                    self.x = int(1)
                    self.y = int(1)
                    self.z = int(0)
                else:
                    self.x = ec_point.x % self.ecc.p
                    self.y = ec_point.y % self.ecc.p
                    self.z = int(1)
                    self.is_on_curve()
        elif (len(args) == 3 or len(args) == 4):
            if (len(args) == 4):
                self.ecc = args[3]
            else:
                self.ecc = secp256r1  # default curve
            self.x = inthex_to_long(args[0]) % self.ecc.p
            self.y = inthex_to_long(args[1]) % self.ecc.p
            self.z = inthex_to_long(args[2]) % self.ecc.p
            # Do not check of point is on the curve when it's point at infinity
            if (not self.is_infinity()):
                self.is_on_curve()
        else:
            raise Exception("Bad parameters in ECPointJ constractor!")

    def __neg__(self):
        return ECPointJ(self.x, self.ecc.p - self.y, self.z, self.ecc)

    def __add__(self, right):
        if right.__class__ != ECPoint:
            raise Exception("Operand on the right is not ECPoint type!")
        return self.add(right)

    def __radd__(self, left):
        self + left  # or self.__add__(left)

    def __sub__(self, right):
        if right.__class__ != ECPoint:
            raise Exception("Operand on the right is not ECPoint type!")
        return self.add(-right)

    #   def __rmul__(self,left):
    #      if type(left) not in (int,long):
    #         raise Exception("Operand on the left is not integer type!")
    #      return self.multiply(left)
    def __str__(self):
        return "[" + hex(self.x) + "], [" + hex(self.y) + "], [" + hex(self.z) + "]"

    def is_on_curve(self):
        'Checking that (x,y,z) is on the curve: y^2 = x^3 + a*x*z^4 + b*z^6'
        if (not ((
                                 self.y ** 2 - self.x ** 3 - self.ecc.a * self.x * self.z ** 4 - self.ecc.b * self.z ** 6) % self.ecc.p) == 0):
            raise Exception("Point is not on the curve!\n" + str(self))
        return True

    def is_infinity(self):
        'Checking that (x,y) is infinity - (1,1,0)'
        if (self.x == 1 and self.y == 1 and self.z == 0):
            return True

    def add(self, b):
        'Point addition: Jacobian + Affine'
        if (self.ecc != b.ecc):
            raise Exception("Different curves for input points! " + str(self.ecc) + ", " + str(b.ecc))
        if (self.is_infinity()):
            return ECPointJ(b)  # convert from Affine to Jacobian
        if (b.is_infinity()):
            return self
        self.is_on_curve()
        b.is_on_curve()
        # Addition formulas
        z1z1 = self.z ** 2
        u2 = b.x * z1z1
        s2 = b.y * self.z * z1z1
        # T1 in Hankerson style
        h = (u2 - self.x) % self.ecc.p
        # T2 in Hankerson style
        r = (2 * (s2 - self.y)) % self.ecc.p
        # Corner cases
        # T1 == 0
        if h == 0:
            # Double
            # T2 == 0
            if r == 0:
                return self.double()
            else:
                return ECPointJ(1, 1, 0, self.ecc)
        hh = h ** 2
        i = 4 * hh
        j = h * i
        v = self.x * i
        # Final values
        x3 = r ** 2 - j - 2 * v
        y3 = r * (v - x3) - 2 * self.y * j
        z3 = (self.z + h) ** 2 - z1z1 - hh
        return ECPointJ(x3, y3, z3, self.ecc)

    def addJ(self, b):
        'Point addition: Jacobian + Jacobian'
        if (self.ecc != b.ecc):
            raise Exception("Different curves for input points! " + str(self.ecc) + ", " + str(b.ecc))
        if (self.is_infinity()):
            return b
        if (b.is_infinity()):
            return self
        self.is_on_curve()
        b.is_on_curve()
        # Addition formulas
        z1z1 = self.z ** 2
        z2z2 = b.z ** 2
        u1 = self.x * z2z2
        u2 = b.x * z1z1
        s1 = self.y * b.z * z2z2
        s2 = b.y * self.z * z1z1
        # T1 in Hankerson style
        h = (u2 - u1) % self.ecc.p
        # T2 in Hankerson style
        r = (2 * (s2 - s1)) % self.ecc.p
        # Corner cases
        # T1 == 0
        if h == 0:
            # Double
            # T2 == 0
            if r == 0:
                return self.double()
            else:
                return ECPointJ(1, 1, 0, self.ecc)
        i = (2 * h) ** 2
        j = h * i
        v = u1 * i
        # Final values
        x3 = r ** 2 - j - 2 * v
        y3 = r * (v - x3) - 2 * s1 * j
        z3 = ((self.z + b.z) ** 2 - z1z1 - z2z2) * h
        return ECPointJ(x3, y3, z3, self.ecc)

    def add2(self, b):
        'Point addition: Jacobian + Affine'
        if (self.ecc != b.ecc):
            raise Exception("Different curves for input points! " + str(self.ecc) + ", " + str(b.ecc))
        if (self.is_infinity()):
            return ECPointJ(b)  # convert from Affine to Jacobian
        if (b.is_infinity()):
            return self
        self.is_on_curve()
        b.is_on_curve()
        # Addition formulas
        t1 = self.z ** 2
        t2 = t1 * self.z
        t1 = t1 * b.x
        t2 = t2 * b.y
        t1 = (t1 - self.x) % self.ecc.p
        t2 = (t2 - self.y) % self.ecc.p
        # Corner cases
        if t1 == 0:
            # Double
            if t2 == 0:
                return self.double()
            else:
                return ECPointJ(1, 1, 0, self.ecc)
        z3 = self.z * t1
        t3 = t1 ** 2
        t4 = t3 * t1
        t3 = t3 * self.x
        t1 = 2 * t3
        x3 = t2 ** 2
        x3 = x3 - t1
        x3 = x3 - t4
        t3 = t3 - x3
        t3 = t3 * t2
        t4 = t4 * self.y
        y3 = t3 - t4
        return ECPointJ(x3, y3, z3, self.ecc)

    def double(self):
        'Point doubling: Jacobian'
        if (self.is_infinity()):
            return self
        self.is_on_curve()
        # Double formulas
        delta = self.z ** 2
        gamma = self.y ** 2
        beta = self.x * gamma
        alpha = 3 * (self.x - delta) * (self.x + delta)
        x3 = alpha ** 2 - 8 * beta
        z3 = (self.y + self.z) ** 2 - gamma - delta
        y3 = alpha * (4 * beta - x3) - 8 * gamma ** 2
        return ECPointJ(x3, y3, z3, self.ecc)


class ECDSA:
    'Class for ECDSA algorithm'
    'Two argument options: (dgst_bitlen, pub_key, prv_key), or (dgst_bitlen, pub_key)'

    def __init__(self, dgst_bitlen, pub_key, prv_key=0):
        if (isinstance(pub_key, ECPoint)):
            self.dgst_bitlen = dgst_bitlen
            self.ecc = pub_key.ecc
            self.pub_key = pub_key
            self.pub_key.is_on_curve()
            self.n_bitlen = bitLen(self.ecc.n)
            self.shr_dgst = 0
            if (self.dgst_bitlen > self.n_bitlen):
                self.shr_dgst = self.dgst_bitlen - self.n_bitlen
        else:
            raise Exception("ECPoint expected (not found)!")
        if (prv_key != 0):
            self.prv_key = inthex_to_long(prv_key) % self.ecc.p
            # Check that private key and public keys match
            genP = ECPoint(self.ecc.gx, self.ecc.gy, self.ecc)
            res = genP.multiply(self.prv_key)
            if (res != self.pub_key):
                raise Exception("Private key and public key don't match!")

    def sign(self, digest):
        'Signing a hash digest'
        digest = inthex_to_long(digest)
        digest = digest >> self.shr_dgst
        # Look for random 'k'
        while True:
            k = randint(1, self.ecc.n - 1)
            R = k * ECPoint(self.ecc.gx, self.ecc.gy, self.ecc)
            if (not R.is_infinity()):
                break
        s = modinv(k, self.ecc.n)
        s = (s * (digest + R.x * self.prv_key)) % self.ecc.n
        r = R.x % self.ecc.n
        return (r, s)

    def sign_k(self, k_in, digest):
        'Signing a hash digest, k is provided from a test vector'
        digest = inthex_to_long(digest)
        digest = digest >> self.shr_dgst
        R = k_in * ECPoint(self.ecc.gx, self.ecc.gy, self.ecc)
        s = modinv(k_in, self.ecc.n)
        s = (s * (digest + R.x * self.prv_key)) % self.ecc.n
        r = R.x % self.ecc.n
        return (r, s)

    def verify(self, digest, r, s):
        'Verifying a signature(hash digest)'
        digest = inthex_to_long(digest)
        digest = digest >> self.shr_dgst
        r = inthex_to_long(r)
        s = inthex_to_long(s)
        w = modinv(s, self.ecc.n)
        u1 = (digest * w) % self.ecc.n
        u2 = (r * w) % self.ecc.n
        R = u1 * ECPoint(self.ecc.gx, self.ecc.gy, self.ecc) + u2 * self.pub_key
        if ((R.x % self.ecc.n) == r):
            return True
        else:
            return False


#
# Tests (only runing them when invoked directly, but not when importing it)
#
if __name__ == '__main__':

    genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)
    infP256 = ECPoint(0, 0, secp256r1)
    # print "Generator point (P256):", genP256
    genP384 = ECPoint(secp384r1.gx, secp384r1.gy, secp384r1)
    infP384 = ECPoint(0, 0, secp384r1)
    # print "Generator point (P384):", genP384

    # Testing add() and double(), 2*(2*P) = 2*P+P+P
    left = genP256 + genP256
    right = left
    left = left + left
    right = right + genP256
    right = right + genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing that 2*P, is the same as P+P
    left = 2 * genP256
    right = genP256 + genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing that 4*P, is the same as P+P+P+P
    left = 4 * genP256
    right = genP256 + genP256 + genP256 + genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing that 3*3*P, is the same as 9*P
    left = 3 * genP256
    left = 3 * left
    right = 9 * genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing negative operation, 4*P - P = 3*P
    left = 4 * genP256 - genP256
    right = 3 * genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing P+0 = P
    left = genP256 + infP256
    right = genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing 0*P = 0
    left = 0 * genP256
    right = infP256
    if (left != right):
        raise Exception("Failed!")

    # Testing 1*P = P
    left = 1 * genP256
    right = genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing n*P = 0
    left = secp256r1.n * genP256
    right = infP256
    if (left != right):
        raise Exception("Failed!")

    # Testing (n-1)*P = -P
    left = (secp256r1.n - 1) * genP256
    right = -genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing add(Jacobian, Affine)
    # Version #1
    left = ECPointJ(2 * genP256) + genP256
    left = ECPoint(left)
    right = 3 * genP256
    if (left != right):
        raise Exception("Failed!")
    # Version #2
    left = ECPointJ(2 * genP256)
    left = left.add2(genP256)
    left = ECPoint(left)
    right = 3 * genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing add(Jacobian, Jacobian)
    left = ECPointJ(genP256) + 2 * genP256
    left = left.addJ(ECPointJ(2 * genP256) + 2 * genP256)
    left = ECPoint(left)
    right = 7 * genP256
    if (left != right):
        raise Exception("Failed!")
    # Testing double(Jacobian) with add(Jacobian, Jacobian)
    left = ECPointJ(genP256) + 2 * genP256
    left = left.addJ(ECPointJ(genP256) + 2 * genP256)
    left = ECPoint(left)
    right = 6 * genP256
    if (left != right):
        raise Exception("Failed!")
    # Testing add(Jacobian, Jacobian) == infinity
    left = ECPointJ(genP256).double().addJ(ECPointJ(-2 * genP256))
    left = ECPoint(left)
    right = 0 * genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing double(Jacobian)
    # Version #1
    left = ECPointJ(genP256).double() + genP256
    left = ECPoint(left)
    right = 3 * genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing double(Jacobian) vs double(Affine)
    # Version #1
    left = ECPointJ(genP256).double().add(2 * genP256)
    left = ECPoint(left)
    right = 4 * genP256
    if (left != right):
        raise Exception("Failed!")
    # Version #2
    left = ECPointJ(genP256).double().add2(2 * genP256)
    left = ECPoint(left)
    right = 4 * genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing add(Jacobian, Affine) == infinity
    # Version #1
    left = ECPointJ(genP256).double().add(-2 * genP256)
    left = ECPoint(left)
    right = 0 * genP256
    if (left != right):
        raise Exception("Failed!")
    left = ECPointJ(genP256).double().add2(-2 * genP256)
    left = ECPoint(left)
    right = 0 * genP256
    if (left != right):
        raise Exception("Failed!")

    # Testing mult(Jacobian) and mult(Affine)
    for i in range(10):
        # Jacobian
        k = randint(1, genP256.ecc.n - 1)
        left = ECPoint(genP256)
        left = genP256.multiplyJ(k)
        # Affine
        right = genP256.multiply(k)
        if (left != right):
            raise Exception("Failed!")

    # Testing octet string conversion with/wihtout compression
    for i in range(10):
        k = randint(1, genP256.ecc.n - 1)
        orig = k * genP256;
        # with compression
        os = orig.output()
        new = ECPoint(secp256r1, os)
        if (new != orig):
            raise Exception("Failed!")
        # without compression
        os = orig.output(False)
        new = ECPoint(secp256r1, os)
        if (new != orig):
            raise Exception("Failed!")

    # Testing ECDSA-256 sign/verify
    digest = getrandbits(256)
    prv_key = randint(1, genP256.ecc.n - 1)
    pub_key = prv_key * genP256
    to_sign = ECDSA(256, pub_key, prv_key)
    to_verify = ECDSA(256, pub_key)
    (r, s) = to_sign.sign(digest)
    if (not to_verify.verify(digest, r, s)):
        raise Exception("ECDSA failed!")

    # Testing ECDSA-256 sign/verify
    # test vector from NIST: engdocs/testvectors/ECDSA_Prime.pdf

    # Digest
    # digest is verified to be the output of SHA-256 as follows:
    from hashlib import sha256

    msg = "Example of ECDSA with P-256"
    dgst = int(sha256(msg).hexdigest(), 16)
    dgst_v = 0xA41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4
    if (dgst_v != dgst):
        raise Exception("Digest from vector is not correct")

    # Long-term key pair
    d_v = 0xC477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96
    Q_x_v = 0xB7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19
    Q_y_v = 0x3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09
    Q = d_v * genP256
    if (Q_x_v != Q.x or Q_y_v != Q.y):
        raise Exception("Public key not as in NIST vector")

    # Ephemeral point
    k_v = 0x7A1A7E52797FC8CAAA435D2A4DACE39158504BF204FBE19F14DBB427FAEE50AE
    R = k_v * genP256
    R_x_v = 0x2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F
    if (R_x_v != R.x):  # This check is redundant as it will be checked as part of the signature
        raise Exception("Ephemeral pulic key not as in NIST vector")

    # Signature
    r_v = 0x2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F
    s_v = 0xDC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1
    to_sign = ECDSA(256, Q, d_v)
    (r, s) = to_sign.sign_k(k_v, dgst_v)
    if (r_v != r or s_v != s):
        raise Exception("Signature does not match vector: FAILURE")

    print("Passed!")
