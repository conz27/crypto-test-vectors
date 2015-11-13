from Crypto.Cipher import AES
import binascii

from array import *
from ecc import *
import os

radix_256 = 2 ** 256
radix_128 = 2 ** 128
radix_32 = 2 ** 32
radix_16 = 2 ** 16
radix_8 = 2 ** 8

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

# Comment the following to obtain different values every time this script is run
seed(333)


class BFKeyExpansion:
    @staticmethod
    def f_k_int_x(k, x):
        aes_obj = AES.new(binascii.unhexlify(k), AES.MODE_ECB)
        s = ""
        for i in range(1, 4):
            #print("x+" + str(i) + ": Input to AES block " + str(i) + " encryption (128 bits):")
            xpi = "{0:032X}".format(x + i)
            #print("0x" + xpi)
            #cArrayDef("[be]", "xp" + str(i), int(xpi, 16), 128 / 8, radix_8, False)
            #print(os.linesep)

            #print("AES_k(x+" + str(i) + "): Output of AES block " + str(i) + " encryption (128 bits):")
            aes_xpi = aes_obj.encrypt(binascii.unhexlify(xpi))
            aes_xpi = binascii.hexlify(aes_xpi)
            #cArrayDef("[be]", "aes_xp" + str(i), int(aes_xpi, 16), 128 / 8, radix_8, False)
            #print(os.linesep)

            #print("AES_k(x+" + str(i) + ") XOR (x+" + str(i) + "): block " + str(i) + " (128 bits):")
            blki_int = int(xpi, 16) ^ int(aes_xpi, 16)
            blki = "{0:032X}".format(blki_int)
            #print("0x" + blki)
            #cArrayDef("[be]", "block_" + str(i), blki_int, 128 / 8, radix_8, False)
            #print(os.linesep)

            s += blki

        return s.upper()

