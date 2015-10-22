from __future__ import print_function
import os
from hashlib import sha256
import hmac
from math import ceil

from array import *

radix_256 = 2**256
radix_128 = 2**128
radix_32 = 2**32
radix_16 = 2**16
radix_8  = 2**8

def sha256_hmac(key, msg):
    '''
    MAC1 is HMAC [in IEEE 1363a, Section 14.4.1]
    This is HMAC with SHA-256,
    with tag output bitlength tbits = 128

    HMAC(K, M) = Hash( (K ^ iPad) || Hash( (K ^ oPad) || M ) )

    Inputs:
    - key: {octet string} authentication key, K (hex encoded bytes)
    - msg: {octet string} message to be authenticated, M (hex encoded bytes)

    Output:
    tag, an octet string of bit length = 128, i.e. 16 octets
    '''

    sha256_in_blk_len = 512/8
    num_blk_in = int(ceil(len(msg)/float(sha256_in_blk_len)))
    tag_len = 128/8

    # If the key is longer than 512 bits, let key = sha256(key)
    # else, right-pad it with 0s to 512-bit long
    if (len(key) > sha256_in_blk_len):
        key = sha256(key.decode('hex')).hexdigest()
    key += "00"*(sha256_in_blk_len - (len(key)/2))

    key_xor_ipad = [Hex(int(x,16) ^ 0x36, radix_8) for x in key]
    key_xor_opad = [Hex(int(x,16) ^ 0x5C, radix_8) for x in key]

    #print("key:          " + key)

    ipad = "36"*sha256_in_blk_len
    #print("ipad:         " + ipad)
    key_xor_ipad = long(key, 16) ^ long(ipad,16)
    key_xor_ipad = "{0:0128x}".format(key_xor_ipad)
    #print("key_xor_ipad: " + key_xor_ipad)

    opad = "5C"*sha256_in_blk_len
    #print("opad:         " + opad)
    key_xor_opad = long(key, 16) ^ long(opad,16)
    key_xor_opad = "{0:0128x}".format(key_xor_opad)
    #print("key_xor_opad: " + key_xor_opad)

    inner_hash = sha256((key_xor_ipad + msg).decode('hex')).hexdigest()
    hmac_out = sha256((key_xor_opad + inner_hash).decode('hex')).hexdigest()

    tag = hmac_out[:tag_len*2]
    #print("tag:          " + tag)
    return tag


# Known HMAC-SHA-256 test vector #1, RFC 4231
known_key1 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
known_msg1 = "4869205468657265"
known_tag1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
if known_tag1 != hmac.new(known_key1.decode("hex"), known_msg1.decode("hex"), sha256).hexdigest():
	raise Exception("Known HMAC #1 doesn't match!")

# Known HMAC-SHA-256 test vector #2, RFC 4231
known_key2 = "4a656665"
known_msg2 = "7768617420646f2079612077616e7420666f72206e6f7468696e673f"
known_tag2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
if known_tag2 != hmac.new(known_key2.decode("hex"), known_msg2.decode("hex"), sha256).hexdigest():
	raise Exception("Known HMAC #2 doesn't match!")

# Known HMAC-SHA-256 test vector #3, RFC 4231
known_key3 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
known_msg3 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
known_tag3 = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
if known_tag3 != hmac.new(known_key3.decode("hex"), known_msg3.decode("hex"), sha256).hexdigest():
	raise Exception("Known HMAC #3 doesn't match!")

# Known HMAC-SHA-256 test vector #4, RFC 4231
known_key4 = "0102030405060708090a0b0c0d0e0f10111213141516171819"
known_msg4 = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
known_tag4 = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
if known_tag4 != hmac.new(known_key4.decode("hex"), known_msg4.decode("hex"), sha256).hexdigest():
	raise Exception("Known HMAC #4 doesn't match!")

# Known HMAC-SHA-256 test vector #5, RFC 4231, with trancation to 128 bits
known_key5 = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
known_msg5 = "546573742057697468205472756e636174696f6e"
known_tag5 = "a3b6167473100ee06e0c796c2955552b"
if known_tag5 != hmac.new(known_key5.decode("hex"), known_msg5.decode("hex"), sha256).hexdigest()[:32]:
	raise Exception("Known HMAC #5 doesn't match!")

# Known HMAC-SHA-256 test vector #6, RFC 4231
known_key6 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
known_msg6 = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"
known_tag6 = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
if known_tag6 != hmac.new(known_key6.decode("hex"), known_msg6.decode("hex"), sha256).hexdigest():
	raise Exception("Known HMAC #6 doesn't match!")

# Known HMAC-SHA-256 test vector #7, RFC 4231
known_key7 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
known_msg7 = "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"
known_tag7 = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
if known_tag7 != hmac.new(known_key7.decode("hex"), known_msg7.decode("hex"), sha256).hexdigest():
	raise Exception("Known HMAC #7 doesn't match!")


key_list = [known_key1, known_key2, known_key3, known_key4, known_key5, known_key6, known_key7]
msg_list = [known_msg1, known_msg2, known_msg3, known_msg4, known_msg5, known_msg6, known_msg7]
tag_list = [known_tag1, known_tag2, known_tag3, known_tag4, known_tag5, known_tag6, known_tag7]
#
# Tests (only runing them when invoked directly, but not when importing it)
#
if __name__ == '__main__':
    print("""
Test vectors for MAC1 with SHA-256 (i.e., HMAC-SHA-256) 
=======================================================
Inputs: authentication key (K), message to be authenticated (M)
Output: Tag (T) of size 128 bits, i.e. 16 octets
""")
    i = 1
    for key, msg, tag in zip(key_list, msg_list, tag_list):

        tag = tag[:32]
        tag_out = sha256_hmac(key, msg)
        #print("known_tag:    " + tag)
        assert tag_out == tag, "error in hmac"

        print("Test Vector #" + str(i) + ":")
        print("---------------")

        # print key
        print("K = 0x" + key)
        cArrayDef("", "key", long(key, 16), len(key)/2, radix_8, False); print(os.linesep)

        #print msg
        print("M = 0x" + msg)
        cArrayDef("", "msg", long(msg, 16), len(msg)/2, radix_8, False); print(os.linesep)

        #print msg
        print("T = 0x" + tag)
        cArrayDef("", "tag", long(tag, 16), len(tag)/2, radix_8, False); print(os.linesep)

        i += 1
