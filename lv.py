#####
# This script generates test vectors for linkage values lv(i,j)
# for i = {0,1} and j randomly chosen in [1,20]
#####

import os
from Crypto.Cipher import AES
from hashlib import sha256

from array import *
from random import *

radix_128 = 2**128
radix_72 = 2**72
radix_32 = 2**32
radix_16 = 2**16
radix_8  = 2**8

# Comment the following to obtain different values every time this script is run
seed(333)


def genls(id, i, la_id, ls_im1, prefix = "ls"):
    if i == 0:
        print(prefix + str(id) + "(0) = AES key (128 bits) = randomly generated 128 bits for every device")
        ls_i = "{0:032X}".format(getrandbits(128))
        print("0x" + ls_i)
        cArrayDef("", prefix + str(id) + "_" + str(i), int(ls_i, 16), 128/8, radix_8, False)
        print(os.linesep)
    else:
        print("SHA-256 input (256 bits) = la_id" + str(id) + " (16-bit) || " + prefix + str(id) + "(" + str(i-1) +")" + " (128-bit) || 0 (112-bit) = ")
        sha256_in = "{0:040X}".format(((la_id << 128) + int(ls_im1, 16)) << 112)
        print("0x" + sha256_in)
        cArrayDef("", "sha256_in"+ str(id) + "_" + str(i), int(sha256_in, 16), 256/8, radix_8, False)
        print(os.linesep)

        print("SHA-256 output (256 bits) = SHA-256(la_id" + str(id) + " || " + prefix + str(id) + "(" + str(i-1) +")) || 0^{112}) =")
        sha256_out = sha256(sha256_in.decode('hex')).hexdigest()
        print("0x" + sha256_out)
        cArrayDef("", "sha256_out"+ str(id) + "_" + str(i), int(sha256_out, 16), 256/8, radix_8, False)
        print(os.linesep)

        print(prefix + str(id) + "(" + str(i) +") = AES key (128 bits) = first 128 bits of SHA-256(la_id" + str(id) + " || " + prefix + str(id) + "(" + str(i-1) +")) =")
        ls_i = "{0:032x}".format(int(sha256_out, 16) >> 128)
        print("0x" + ls_i)
        cArrayDef("", prefix + str(id)  + "_" + str(i), int(ls_i, 16), 128/8, radix_8, False)
        print(os.linesep)

    return ls_i

def genplv(id, i, la_id, ls_i, j, prefix = "plv", keyname = "ls"):
    aes_obj = AES.new(ls_i.decode('hex'), AES.MODE_ECB)

    print("AES input plaintext (128 bits) = la_id" + str(id) + " (16-bit) || j (32-bit) || 0 (80-bit) = ")
    aes_in_j = "{0:032X}".format((la_id * radix_32 + j) << 80)
    print("0x" + aes_in_j)
    cArrayDef("", "aes_in"+ str(id) + "_j", int(aes_in_j, 16), 128/8, radix_8, False)
    print(os.linesep)

    print("AES output (128 bits) = AES_" + keyname + str(id) + "(" + str(i) +") (la_id" + str(id) + " || j || 0^{80}) =")
    aes_out_j = aes_obj.encrypt(aes_in_j.decode('hex')).encode('hex')
    print("0x" + aes_out_j.upper())
    cArrayDef("", "aes_out"+ str(id) + "_" + str(i) + "_j", int(aes_out_j, 16), 128/8, radix_8, False)
    print(os.linesep)

    print(prefix + str(id) + "(" + str(i) + ",j) = AES output XOR AES input (72 bits) = ")
    plv_i_j = (int(aes_in_j, 16) ^ int(aes_out_j, 16)) >> (128-72)
    print(Hex(plv_i_j, radix_72))
    cArrayDef("", prefix + str(id) + "_" + str(i) + "_j", plv_i_j, 72/8, radix_8, False)
    print(os.linesep)

    return plv_i_j

def genlv(i, plv1_i_j, plv2_i_j, g=""):
    print(g+"lv(" + str(i) + ",j) = " + g + "plv1(" + str(i) + ",j) XOR " + g + "plv2(" + str(i) + ",j)")
    lv_i_j = plv1_i_j ^ plv2_i_j
    print(Hex(lv_i_j, radix_72))
    cArrayDef("", g+"lv_" + str(i) +"_j", lv_i_j, 72/8, radix_8, False)
    print(os.linesep)

    return lv_i_j
    
if __name__ == '__main__':

    print("""
Test vectors for Linkage Values lv(i,j)
for i = {0,1} and j randomly chosen in [1,20] for test purposes
===============================================================
""")

    print("LA1 ID (16 bits) =")
    la_id1 = getrandbits(16)
    print(Hex(la_id1, radix_16) + os.linesep)

    print("LA2 ID (16 bits) =")
    la_id2 = getrandbits(16)
    print(Hex(la_id2, radix_16) + os.linesep)

    print("""
i = 0
=====
j is randomly chosen in [1,20]
""")

    print("j (in range [1,20], padded to 32 bits) =")
    j = randint(1,20)
    print(Hex(j, radix_32) + os.linesep)

    print("LA1")
    print("---")
    ls1_0 = genls(1, 0, None, None)
    plv1_0_j = genplv(1, 0, la_id1, ls1_0, j)

    print("LA2")
    print("---")
    ls2_0 = genls(2, 0, None, None)
    plv2_0_j = genplv(2, 0, la_id2, ls2_0, j)

    print("lv(0,j)")
    print("-------")
    lv_0_j = genlv(0, plv1_0_j, plv2_0_j)

    print("""
i = 1
=====
j is randomly chosen in [1,20]
""")

    print("j (in range [1,20], padded to 32 bits) =")
    j = randint(1,20)
    print(Hex(j, radix_32) + os.linesep)

    print("LA1")
    print("---")
    ls1_1 = genls(1, 1, la_id1, ls1_0)
    plv1_1_j = genplv(1, 1, la_id1, ls1_1, j)

    print("LA2")
    print("---")
    ls2_1 = genls(2, 1, la_id2, ls2_0)
    plv2_1_j = genplv(2, 1, la_id2, ls2_1, j)

    print("lv(1,j)")
    print("-------")
    lv_1_j = genlv(1, plv1_1_j, plv2_1_j)
