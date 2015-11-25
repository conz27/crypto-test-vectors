#####
# This script generates test vectors for group linkage values glv(i,j)
# for i = {0,1} and j randomly chosen 32-bit value.
#####

from lv import *


def genei(ik, j, k):
    aes_obj = AES.new(binascii.unhexlify(ik), AES.MODE_ECB)
    aes_in_j_k = "{0:032X}".format(((j << 32) + k) << 64)
    aes_out_j_k = aes_obj.encrypt(binascii.unhexlify(aes_in_j_k))
    aes_out_j_k = binascii.hexlify(aes_out_j_k)
    ei_j_k = int(aes_in_j_k, 16) ^ int(aes_out_j_k, 16)
    return ei_j_k

