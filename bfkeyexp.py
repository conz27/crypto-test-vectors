# TODO: fix; requires pycrypto (wrt dependency thinning)
from Crypto.Cipher import AES
import binascii

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

