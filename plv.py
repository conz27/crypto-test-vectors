from __future__ import print_function
import os
from Crypto.Cipher import AES
from hashlib import sha256

from array import *
from random import *

radix_128 = 2**128
radix_32 = 2**32
radix_16 = 2**16
radix_8  = 2**8

#Uncomment the following to obtain different values every time this script is run
seed(333)


def genls(id, i, la_id, ls_im1):
    if i == 0:
        print("ls" + str(id) + "(0) = AES key (128 bits) = randomly generated 128 bits ")
        ls_i = "{0:032X}".format(getrandbits(128))
        print("0x" + ls_i)
        cArrayDef("", "ls" + str(id) + "_" + str(i), long(ls_i, 16), 128/8, radix_8, False)
        print(os.linesep)
    else:
        print("SHA-256 input (128 bits) = la_id" + str(id) + "^{32-bit} || ls" + str(id) + "(" + str(i-1) +")" + "^{128-bit} = ")
        sha256_in = "{0:040X}".format((la_id << 128) + long(ls_im1, 16))
        print("0x" + sha256_in)
        cArrayDef("", "sha256_in"+ str(id) + "_" + str(i), long(sha256_in, 16), (32+128)/8, radix_8, False)
        print(os.linesep)

        print("SHA-256 output (256 bits) = SHA-256(la_id" + str(id) + " || ls" + str(id) + "(" + str(i-1) +"))")
        sha256_out = sha256(sha256_in.decode('hex')).hexdigest()
        print("0x" + sha256_out)
        cArrayDef("", "sha256_out"+ str(id) + "_" + str(i), long(sha256_out, 16), 256/8, radix_8, False)
        print(os.linesep)

        print("ls" + str(id) + "(" + str(i) +") = AES key (128 bits) = first 128 bits of SHA-256(la_id" + str(id) + " || ls" + str(id) + "(" + str(i-1) +"))")
        ls_i = "{0:032x}".format(long(sha256_out, 16) >> 128)
        print("0x" + ls_i)
        cArrayDef("", "ls" + str(id)  + "_" + str(i), long(ls_i, 16), 128/8, radix_8, False)
        print(os.linesep)

    return ls_i

def genplv(id, i, la_id, ls_i, j):
    aes_obj = AES.new(ls_i.decode('hex'), AES.MODE_ECB)

    print("AES input plaintext (128 bits) = 0^{64-bit} || la_id" + str(id) + "^{32-bit} || j^{32-bit} = ")
    aes_in_j = "{0:032X}".format(la_id * radix_32 + j)
    print("0x" + aes_in_j)
    cArrayDef("", "aes_in"+ str(id) + "_j", long(aes_in_j, 16), 128/8, radix_8, False)
    print(os.linesep)

    print("AES output (128 bits) = AES_ls" + str(id) + "(" + str(i) +") (la_id" + str(id) + " || j)")
    aes_out_j = aes_obj.encrypt(aes_in_j.decode('hex')).encode('hex')
    print("0x" + aes_out_j.upper())
    cArrayDef("", "aes_out"+ str(id) + "_" + str(i) + "_j", long(aes_out_j, 16), 128/8, radix_8, False)
    print(os.linesep)

    print("plv" + str(id) + "(" + str(i) + ",j) = AES output XOR AES input (128 bits) = ")
    plv_i_j = long(aes_in_j, 16) ^ long(aes_out_j, 16)
    print(Hex(plv_i_j, radix_128))
    cArrayDef("", "plv" + str(id) + "_" + str(i) + "_j", plv_i_j, 128/8, radix_8, False)
    print(os.linesep)

    return plv_i_j

def genlv(i, plv1_i_j, plv2_i_j):
    print("lv(" + str(i) + ",j) = plv1(" + str(i) + ",j) XOR plv2(" + str(i) + ",j)")
    lv_i_j = plv1_i_j ^ plv2_i_j
    print(Hex(lv_i_j, radix_128))
    cArrayDef("", "lv_" + str(i) +"_j", lv_i_j, 128/8, radix_8, False)
    print(os.linesep)

    return lv_i_j
    

print("LA1 ID (16 bits, padded to 32 bits) =")
la_id1 = getrandbits(16)
print(Hex(la_id1, radix_32))
print()

print("LA2 ID (16 bits, padded to 32 bits) =")
la_id2 = getrandbits(16)
print(Hex(la_id2, radix_32))
print()

print("""
i = 0
-----
j is randomly chosen in [1,20]
""")

print("j (in range [1,20], padded to 32 bits) =")
j = randint(1,20)
print(Hex(j, radix_32))
print()

ls1_0 = genls(1, 0, None, None)
plv1_0_j = genplv(1, 0, la_id1, ls1_0, j)

ls2_0 = genls(2, 0, None, None)
plv2_0_j = genplv(2, 0, la_id2, ls2_0, j)

lv_0_j = genlv(0, plv1_0_j, plv2_0_j)

print("""
i = 1
-----
j is randomly chosen in [1,20]
""")

print("j (in range [1,20], padded to 32 bits) =")
j = randint(1,20)
print(Hex(j, radix_32))
print()

ls1_1 = genls(1, 1, la_id1, ls1_0)
plv1_1_j = genplv(1, 1, la_id1, ls1_1, j)

ls2_1 = genls(2, 1, la_id2, ls2_0)
plv2_1_j = genplv(2, 1, la_id2, ls2_1, j)

lv_1_j = genlv(1, plv1_1_j, plv2_1_j)
