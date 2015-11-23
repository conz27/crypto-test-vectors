#####
# This script generates test vectors for linkage values lv(i,j)
# for i = {0,1} and j randomly chosen in [1,20]
#####

import os
import binascii
from Crypto.Cipher import AES
from hashlib import sha256
from array import *
from random import *

radix_128 = 2 ** 128
radix_72 = 2 ** 72
radix_32 = 2 ** 32
radix_16 = 2 ** 16
radix_8 = 2 ** 8


def genls(id, i, la_id, ls_im1, prefix="ls"):
    if i == 0:
        ls_i = "{0:032X}".format(getrandbits(128))
    else:
        sha256_in = "{0:040X}".format(((la_id << 128) + int(ls_im1, 16)) << 112)
        sha256_out = sha256(binascii.unhexlify(sha256_in))
        sha256_out = sha256_out.hexdigest()
        ls_i = "{0:032x}".format(int(sha256_out, 16) >> 128)
    return ls_i


def genplv(id, i, la_id, ls_i, j, prefix="plv", keyname="ls"):
    aes_obj = AES.new(binascii.unhexlify(ls_i), AES.MODE_ECB)
    aes_in_j = "{0:032X}".format((la_id * radix_32 + j) << 80)
    aes_out_j = aes_obj.encrypt(binascii.unhexlify(aes_in_j))
    aes_out_j = binascii.hexlify(aes_out_j)
    plv_i_j = (int(aes_in_j, 16) ^ int(aes_out_j, 16)) >> (128 - 72)
    return plv_i_j


def genlv(i, plv1_i_j, plv2_i_j, g=""):
    lv_i_j = plv1_i_j ^ plv2_i_j
    return lv_i_j
