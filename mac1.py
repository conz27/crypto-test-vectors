import os
from hashlib import sha256
import hmac
from math import ceil

import binascii

from array import *

radix_256 = 2 ** 256
radix_128 = 2 ** 128
radix_32 = 2 ** 32
radix_16 = 2 ** 16
radix_8 = 2 ** 8


def sha256_hmac(key, msg):
    """
    MAC1 is HMAC [in IEEE 1363a, Section 14.4.1]
    This is HMAC with SHA-256,
    with tag output bitlength tbits = 128

    HMAC(K, M) = Hash( (K ^ iPad) || Hash( (K ^ oPad) || M ) )

    Inputs:
    - key: {octet string} authentication key, K (hex encoded bytes)
    - msg: {octet string} message to be authenticated, M (hex encoded bytes)

    Output:
    tag, an octet string of bit length = 128, i.e. 16 octets
    """

    sha256_in_blk_len = 512 // 8
    num_blk_in = int(ceil(len(msg) / float(sha256_in_blk_len)))
    tag_len = 128 // 8

    # If the key is longer than 512 bits, let key = sha256(key)
    # else, right-pad it with 0s to 512-bit long
    if len(key) > sha256_in_blk_len:
        key = sha256(key.decode('hex')).hexdigest()
    key += "00" * (sha256_in_blk_len - (len(key) // 2))

    key_xor_ipad = [Hex(int(x, 16) ^ 0x36, radix_8) for x in key]
    key_xor_opad = [Hex(int(x, 16) ^ 0x5C, radix_8) for x in key]

    # print("key:          " + key)

    ipad = "36" * sha256_in_blk_len
    # print("ipad:         " + ipad)
    key_xor_ipad = int(key, 16) ^ int(ipad, 16)
    key_xor_ipad = "{0:0128x}".format(key_xor_ipad)
    # print("key_xor_ipad: " + key_xor_ipad)

    opad = "5C" * sha256_in_blk_len
    # print("opad:         " + opad)
    key_xor_opad = int(key, 16) ^ int(opad, 16)
    key_xor_opad = "{0:0128x}".format(key_xor_opad)
    # print("key_xor_opad: " + key_xor_opad)

    inner_hash = sha256(binascii.unhexlify(key_xor_ipad + msg)).hexdigest()
    hmac_out = sha256(binascii.unhexlify(key_xor_opad + inner_hash)).hexdigest()

    tag = hmac_out[:tag_len * 2]
    # print("tag:          " + tag)
    return tag
