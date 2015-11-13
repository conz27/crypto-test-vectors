from ecc import *

radix_256 = 2 ** 256
radix_8 = 2 ** 8

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)


def ecdh(a, B):
    a = int(a, 16)
    aB = a * B
    Z = aB.x
    ss = "{0:0>{width}X}".format(Z, width=bitLen(B.ecc.n) // 4).upper()
    return ss
