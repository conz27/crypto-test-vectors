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

print("""
i = 0
-----
""")

#print(os.linesep)
print("j (in range [1,20], padded to 32 bits) =")
j = randint(1,20)
print(Hex(j, radix_32))

#print(os.linesep)
print("LA1 ID (16 bits, padded to 32 bits) =")
la_id1 = getrandbits(16)
print(Hex(la_id1, radix_32))
cArrayDef("", "la_id1", la_id1, 32/8, radix_8, False) ##

print(os.linesep)
print("ls1(0) = AES key (128 bits) =")
ls1_0 = "{0:032x}".format(getrandbits(128))
print("0x" + ls1_0)
cArrayDef("", "ls1(0)", long(ls1_0, 16), 128/8, radix_8, False)

aes_obj = AES.new(ls1_0.decode('hex'), AES.MODE_ECB)

print(os.linesep)
print("AES input plaintext (128 bits) = 0^{64-bit} || la_id1^{32-bit} || j^{32-bit} = ")
aes_in_j = "{0:032X}".format(la_id1 * radix_32 + j)
print("0x" + aes_in_j)
cArrayDef("", "aes_in_j", long(aes_in_j, 16), 128/8, radix_8, False)


print(os.linesep)
print("AES output (128 bits) = ")
aes_out_j = aes_obj.encrypt(aes_in_j.decode('hex')).encode('hex')
print("0x" + aes_out_j.upper())
cArrayDef("", "aes_out_j", long(aes_out_j, 16), 128/8, radix_8, False)

print(os.linesep)
print("plv1(i,j) = AES output XOR AES input (128 bits) = ")
plv1_0_j = long(aes_in_j, 16) ^ long(aes_out_j, 16)
print(Hex(plv1_0_j,radix_128))
cArrayDef("", "plv1_0_j", plv1_0_j, 128/8, radix_8, False)
