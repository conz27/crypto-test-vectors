from __future__ import print_function
import os
from hashlib import sha256
from random import *
from math import ceil

from array import *

radix_256 = 2**256
radix_128 = 2**128
radix_32 = 2**32
radix_16 = 2**16
radix_8  = 2**8

#Uncomment the following to obtain different values every time this script is run
seed(333)

def sha256_kdf(ss, kdp, dl):
    '''
    This KDF is KDF2 [in IEEE 1363a, Section 13.2] with SHA-256.
    Inputs:
    - ss:  {octet string} shared secret (hex encoded bytes)
    - kdp: {octet string} key derivation parameter (hex encoded bytes)
    - dl:  {integer}      desired output length in octets

    Output:
    octet string of the desired length, dl.
    '''

    assert dl >= 0, 'dl should be positive integer'

    hash_blk_len = 256/8
    num_blk_out = int(ceil(dl/float(hash_blk_len)))

    kdf_out = ''
    for i in range(1, num_blk_out+1):
        hash_input = (ss + "{0:08x}".format(i) + kdp).decode('hex')
        kdf_out += sha256(hash_input).hexdigest()

    kdf_out = kdf_out[:dl*2]
    return kdf_out

# Test vector #1, ANSI X9.63
# 	[SHA-256]
# 	[shared secret length = 192]
# 	[SharedInfo length = 0]
# 	[key data length = 128]
known_ss1 = "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08"
known_kdp1 = ""
known_key1 = "443024c3dae66b95e6f5670601558f71"

# Test vector #2, ANSI X9.63
# 	[SHA-256]
# 	[shared secret length = 192]
# 	[SharedInfo length = 0]
# 	[key data length = 128]
known_ss2 = "96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4"
known_kdp2 = ""
known_key2 = "b6295162a7804f5667ba9070f82fa522"

# Test vector #3, ANSI X9.63
# 	[SHA-256]
# 	[shared secret length = 192]
# 	[SharedInfo length = 128]
# 	[key data length = 1024]
known_ss3 = "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d"
known_kdp3 = "75eef81aa3041e33b80971203d2c0c52"
known_key3 = "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21"

# Test vector #4, ANSI X9.63
# 	[SHA-256]
# 	[shared secret length = 192]
# 	[SharedInfo length = 128]
# 	[key data length = 1024]
known_ss4 = "7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a"
known_kdp4 = "d65a4812733f8cdbcdfb4b2f4c191d87"
known_key4 = "c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365acbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b"

print("""
Test vectors for KDF2
=====================
""")

ss_list  = [known_ss1, known_ss2, known_ss3, known_ss4]
kdp_list = [known_kdp1, known_kdp2, known_kdp3, known_kdp4]
key_list = [known_key1, known_key2, known_key3, known_key4]
i = 1
for ss, kdp, key in zip(ss_list, kdp_list, key_list):
    dl = len(key)/2
    kdf_out = sha256_kdf(ss, kdp, dl)
    assert kdf_out == key, "error in kdf"
    i += 1

    print("Test Vector #" + str(i) + ":")
    print("---------------")
    print("Inputs: shared secret (ss), key derivation parameter (kdp), desired octet string length (dl)")
    # print shared secret
    print("ss = 0x" + ss)
    cArrayDef("", "ss", long(ss, 16), len(ss)/(2*8), radix_8, False); print(os.linesep)
    
    #print key derivation parameter
    if (kdp == ""):
        print("kdp = \"\""); print()
    else:
        print("kdp = 0x" + kdp)
        cArrayDef("", "kdp", long(kdp, 16), len(kdp)/(2*8), radix_8, False); print(os.linesep)

    #print desired length
    print("dl = " + str(dl) + " octets"); print(os.linesep)
