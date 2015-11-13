import os
from hashlib import sha256
from math import ceil

import binascii

from array import *

radix_256 = 2 ** 256
radix_128 = 2 ** 128
radix_32 = 2 ** 32
radix_16 = 2 ** 16
radix_8 = 2 ** 8


def sha256_kdf(ss, kdp, dl):
    """
    This KDF is KDF2 [in IEEE 1363a, Section 13.2] with SHA-256.

    KDF(SS, KDP) = Hash(SS || counter || KDP)
    concatinating output blocks for counter in [1, ceil(dl/block_len)]

    Inputs:
    - ss:  {octet string} shared secret (hex encoded bytes)
    - kdp: {octet string} key derivation parameter (hex encoded bytes)
    - dl:  {integer}      desired output length in octets

    Output:
    octet string of the desired length, dl.
    """

    assert dl >= 0, 'dl should be positive integer'

    sha256_blk_len = 256 / 8
    num_blk_out = int(ceil(dl / float(sha256_blk_len)))

    kdf_out = ''
    for i in range(1, num_blk_out + 1):
        hash_input = binascii.unhexlify(ss + "{0:08x}".format(i) + kdp)
        kdf_out += sha256(hash_input).hexdigest()

    kdf_out = kdf_out[:dl * 2]
    return kdf_out

