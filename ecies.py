from __future__ import print_function
import os

from array import *
from ecc import *
from ecdh import ecdh
from kdf import sha256_kdf
from mac1 import sha256_hmac

#Uncomment the following to obtain different values every time this script is run
seed(333)

radix_256 = 2**256
radix_128 = 2**128
radix_32 = 2**32
radix_16 = 2**16
radix_8  = 2**8

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

def ecies_enc(R, k, p1, v=None):
    '''
    ECIES Encryption as per 1609.2,
    Used to wrap AES-CCM 128-bit keys

    Inputs:
    - R:  {ec256 point} Recipient public key
    - k:  {octet string} AES-CCM 128-bit key to be wrapped (128 bits)
    - P1: {octet string} SHA-256 hash of some defined recipient info or of an empty string (256 bits)

    Outputs:
    - V:  {ec256 point} Sender's ephemeral public key
    - C:  {octet string} Ciphertext, i.e. enc(k) (128 bits)
    - T:  {octet string} Authentication tag, (128 bits)
    '''

    k_len = 128/8
    p1_len = 256/8
    assert len(k) == k_len*2, "input k must be of octet length: " + str(k_len)
    assert len(p1) == p1_len*2, "input P1 must be of octet length: " + str(p1_len)
    assert R.is_on_curve(), "recipient's public key must be a point on the curve P-256"

    # Generate Sender's ephemeral key pair (v, V)
    if (v == None):
        v_long = randint(1, genP256.ecc.n-1)
        v = "{0:0>{width}X}".format(v_long, width=bitLen(genP256.ecc.n)*2/8)
    else:
        v_long = long(v, 16)
    V = v_long*genP256

    # ECDH: compute a shared secret (sender's private key, recipient's public key)
    ss = ecdh(v, R)

    # Derive K1 and K2 with KDF
    K1_len = 128/8
    K2_len = 256/8
    dl = K1_len + K2_len
    K1_K2 = sha256_kdf(ss, p1, dl)

    # Encrypt k by XORing it with K1
    K1 = K1_K2[:K1_len*2]
    enc_k = long(k, 16) ^ long(K1, 16)
    C = "{0:0>{width}X}".format(enc_k, width=k_len*2)

    # Calculate MAC1 on C with key K2
    K2 = K1_K2[K1_len*2:]
    T = sha256_hmac(K2, C)

    return V, C, T, v

def ecies_dec(V, C, T, r, p1):
    '''
    ECIES Decryption as per 1609.2,
    Used to unwrap AES-CCM 128-bit keys

    Inputs:
    - V:  {ec256 point} Sender's ephemeral public key
    - C:  {octet string} Ciphertext, i.e. enc(k) (128 bits)
    - T:  {octet string} Authentication tag, (128 bits)
    - r:  {octet string} Recipient private key (256 bits)
    - P1: {octet string} SHA-256 hash of some defined recipient info or of an empty string (256 bits)

    Outputs:
    - k:  {octet string} AES-CCM 128-bit key, unwrapped (128 bits)
    '''
    k_len = 128/8
    p1_len = 256/8
    assert len(C) == k_len*2, "input C must be of octet length: " + str(k_len)
    assert len(p1) == p1_len*2, "input P1 must be of octet length: " + str(p1_len)
    assert V.is_on_curve(), "sender's public key must be a point on the curve P-256"

    # ECDH: compute a shared secret (recipient's private key, sender's public key)
    ss = ecdh(r, V)

    # Derive K1 and K2 with KDF
    K1_len = 128/8
    K2_len = 256/8
    dl = K1_len + K2_len
    K1_K2 = sha256_kdf(ss, p1, dl)

    # Calculate MAC1 on C with key K2
    K2 = K1_K2[K1_len*2:]
    T_dec = sha256_hmac(K2, C)

    if T_dec != T:
        return "-1"
    
    # Decrypt k by XORing C with K1
    K1 = K1_K2[:K1_len*2]
    dec_C = long(C, 16) ^ long(K1, 16)
    k = "{0:0>{width}X}".format(dec_C, width=k_len*2)

    return k

        
v  = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"

k1  = "9169155B08B07674CBADF75FB46A7B0D"
p11 = "A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9"
r1  = "060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085"
Rx1 = "8C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11"
Ry1 = "1270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E"

k2  = "687E9757DEBFD87B0C267330C183C7B6"
p12 = "05BED5F867B89F30FE5552DF414B65B9DD4073FC385D14921C641A145AA12051"
r2  = "DA5E1D853FCC5D0C162A245B9F29D38EB6059F0DB172FB7FDA6663B925E8C744"
Rx2 = "8008B06FC4C9F9856048DA186E7DC390963D6A424E80B274FB75D12188D7D73F"
Ry2 = "2774FB9600F27D7B3BBB2F7FCD8D2C96D4619EF9B4692C6A7C5733B5BAC8B27D"


print("""
Test vectors for ECIES as per 1609.2 v3
=======================================
ECIES Encryption as per 1609.2,
Used to wrap AES-CCM 128-bit keys

Encryption Inputs:
- R:  {ec256 point} Recipient public key
- k:  {octet string} AES-CCM 128-bit key to be wrapped (128 bits)
- P1: {octet string} SHA-256 hash of some defined recipient info or of an empty string (256 bits)

Encryption Outputs:
- V:  {ec256 point} Sender's ephemeral public key
- C:  {octet string} Ciphertext, i.e. enc(k) (128 bits)
- T:  {octet string} Authentication tag, (128 bits)

The encryption output is randomised, due to the ephemeral sender's key (v,V)
In the script, for testing purpose:
- v is an optional input to ecies_enc()
- v is an output of ecies_enc() to be printed in the test vectors
""")

v_list   = [v, None, v, None]
k_list   = [k1, k1, k2, k2]
p1_list  = [p11, p11, p12, p12]
r_list   = [r1, r1, r2, r2]
Rx_list  = [Rx1, Rx1, Rx2, Rx2]
Ry_list  = [Ry1, Ry1, Ry2, Ry2]

i = 1
for v, k, p1, r, Rx, Ry in zip(v_list, k_list, p1_list, r_list, Rx_list, Ry_list):
    R = ECPoint(long(Rx, 16), long(Ry, 16), secp256r1)
    V, C, T, v = ecies_enc(R, k, p1, v=v)
    k_dec = ecies_dec(V, C, T, r, p1)
    assert k_dec == k, "decrypted key differs from original key"

    print("Test Vector #" + str(i) + ":")
    print("===============")

    print("Sender's ephemeral private key:")
    print("v = 0x" + v)
    cArrayDef("", "v", long(v, 16), len(v)/2, radix_8, False); print(os.linesep)

    print("AES key to be encrypted (wrapped):")
    print("k = 0x" + k)
    cArrayDef("", "k", long(k, 16), len(k)/2, radix_8, False); print(os.linesep)

    print("Hash(RecipientInfo):")
    print("P1 = 0x" + k)
    cArrayDef("", "P1", long(k, 16), len(k)/2, radix_8, False); print(os.linesep)

    print("Recipient's private key (Decryption input):")
    print("r = 0x" + r)
    cArrayDef("", "r", long(r, 16), len(r)/2, radix_8, False); print(os.linesep)

    print("Recipient's public key (x-coordinate):")
    print("Rx = 0x" + Rx)
    cArrayDef("", "Rx", long(Rx, 16), len(Rx)/2, radix_8, False); print(os.linesep)

    print("Recipient's public key (y-coordinate):")
    print("Ry = 0x" + Ry)
    cArrayDef("", "Ry", long(Ry, 16), len(Ry)/2, radix_8, False); print(os.linesep)

    print("Encryption Output:")
    print("------------------")

    print("Sender's ephemeral public key (x-coordinate):")
    print("Vx = " + Hex(V.x, radix_256))
    cArrayDef("", "Vx", V.x, 256/8, radix_8, False); print(os.linesep)

    print("Sender's ephemeral public key (y-coordinate):")
    print("Vy = " + Hex(V.y, radix_256))
    cArrayDef("", "Vx", V.y, 256/8, radix_8, False); print(os.linesep)

    print("Encrypted (wrapped) AES key:")
    print("C = 0x" + C)
    cArrayDef("", "C", long(C, 16), len(C)/2, radix_8, False); print(os.linesep)

    print("Authentication tag:")
    print("T = 0x" + T)
    cArrayDef("", "T", long(T, 16), len(T)/2, radix_8, False); print(os.linesep)

    i += 1
