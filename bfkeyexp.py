# TODO: fix; requires pycrypto (wrt dependency thinning)
from Crypto.Cipher import AES
from ecc import *
import binascii


radix_256 = 2 ** 256
radix_128 = 2 ** 128
radix_32 = 2 ** 32
radix_16 = 2 ** 16
radix_8 = 2 ** 8

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)


def f_k_int_x(k, x):
    aes_obj = AES.new(binascii.unhexlify(k), AES.MODE_ECB)
    s = ""
    for i in range(1, 4):
        xpi = "{0:032X}".format(x + i)
        aes_xpi = aes_obj.encrypt(binascii.unhexlify(xpi))
        aes_xpi = binascii.hexlify(aes_xpi)
        blki_int = int(xpi, 16) ^ int(aes_xpi, 16)
        blki = "{0:032X}".format(blki_int)
        s += blki
    return s.upper()

