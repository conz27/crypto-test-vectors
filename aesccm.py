from __future__ import print_function
import os
from Crypto.Cipher import AES

from array import *

radix_256 = 2**256
radix_128 = 2**128
radix_32 = 2**32
radix_16 = 2**16
radix_8  = 2**8

def aes_ccm_enc(key, nonce, msg):
    '''
    This is AES-CCM-128 implementation for 1609.2 v3
    It is based on NIST SP 800-38C (and RFC 3610) with the following:
    - Adata = 0, i.e. no associated authenticated data
    - t=16, i.e. tag length is 16 octets
    - n=12, i.e. Nonce length is 12 octets
    - q=3, i.e. the message length in octets is encoded in 3 octets

    Inputs:
    - key:       {octet string} AES-CCM key, K (hex encoded bytes)
    - nonce:     {octet string} nonce, N (hex encoded bytes)
    - plaintext: {octet string} plaintext to be encrypted and authenticated, P (hex encoded bytes)

    Output:
    ciphertext || tag = C || T {octet string}
    '''

    aes128_blk_len = 128/8
    key_len = 128/8
    tag_len = 16
    nonce_len = 12
    assert len(nonce) == nonce_len*2, "nonce must be of length 12 octets"
    assert len(key) == key_len*2, "key must be of length 16 octets"
    msg_len_len = 15 - nonce_len
    msg_blk_len = (len(msg)/2) / aes128_blk_len    # not counting the last non-full block, if any
    last_bytes = (len(msg)/2) % aes128_blk_len

    aes = AES.new(key.decode('hex'), AES.MODE_ECB)

    # Authentication: AES-CBC-MAC(K, N, M)
    # Block B0

##  L: #octets in length of message field
##   The first block B_0 is formatted as follows, where the length of the message field
##   is encoded in most-significant-byte-first order:
##
##      Octet Number   Contents
##      ------------   ---------
##      0              Flags
##      1 ... 15-L     Nonce N
##      16-L ... 15    length of message field
##
##   Within the first block B_0, the Flags field is formatted as follows:
##
##      Bit Number   Contents
##      ----------   ----------------------
##      7            Reserved (always zero)
##      6            Adata
##      5 ... 3      (#octets in authentication field - 2)/2
##      2 ... 0      (#octest in length of message field -1)

##         X_1     := E(K, B_0)
##         X_{i+1} := E(K, X_i XOR B_i)
##         T := first-M-bytes( X_n+1 )

    B_0_0 ="{0:02X}".format( (((tag_len - 2)/2) << 3) | (msg_len_len - 1) )
    nonce_padded = "{0:0>{width}}".format(nonce, width=nonce_len*2)
    msg_len = "{0:0>{width}X}".format(len(msg)/2, width=msg_len_len*2)
    B_0 = B_0_0 + nonce_padded + msg_len
    
    X = aes.encrypt(B_0.decode('hex')).encode('hex')
    for i in range(1, msg_blk_len+1):
        B_i = msg[(i-1)*aes128_blk_len*2:i*aes128_blk_len*2]
        xor_out = "{0:0{width}X}".format((long(B_i, 16) ^ long(X, 16)), width=aes128_blk_len*2)
        X = aes.encrypt(xor_out.decode('hex')).encode('hex')

    # handling the last block
    if (last_bytes):
        B_i = "{0:0<{width}}".format(msg[(msg_blk_len)*aes128_blk_len*2:len(msg)], width=aes128_blk_len*2)
        xor_out = "{0:0{width}X}".format((long(B_i, 16) ^ long(X, 16)), width=aes128_blk_len*2)
        X = aes.encrypt(xor_out.decode('hex')).encode('hex')
    # T := X[:tag_len*2]
    # Authentication tag T is the same length as AES block here so no truncation needed
    # Final tag is encrypted and is calculated after the first encrypted block is calculated

    # Encryption: AES-CTR(K, N, M)
##    key stream blocks:
##      S_i := E( K, A_i )   for i=0, 1, 2, ...
##    Ciphertext:
##      C_i := B_i XOR S_i   for i=1,2,...
##    Tag:
##      U   := T XOR S_0     truncated to tag length
##
##   The values A_i are formatted as follows, where the Counter field i is
##   encoded in most-significant-byte first order:
##
##      Octet Number   Contents
##      ------------   ---------
##      0              Flags
##      1 ... 15-L     Nonce N
##      16-L ... 15    Counter i
##
    # Flags byte = (#octest in length of message field-1) = L-1

    A_0_0 ="{0:02X}".format(msg_len_len - 1)
    # nonce_padded as calculated above
    counter = "{0:0{width}X}".format(0, width=msg_len_len*2)
    A_0 = A_0_0 + nonce_padded + counter

    S_0 = aes.encrypt(A_0.decode('hex')).encode('hex')
    U = "{0:0{width}X}".format((long(X, 16) ^ long(S_0, 16)), width=aes128_blk_len*2)
    U = U[:tag_len*2]

    C = ""
    for i in range(1, msg_blk_len+1):
        counter = "{0:0{width}X}".format(i, width=msg_len_len*2)
        A_i = A_0_0 + nonce_padded + counter
        S_i = aes.encrypt(A_i.decode('hex')).encode('hex')
        B_i = msg[(i-1)*aes128_blk_len*2:i*aes128_blk_len*2]
        C_i = "{0:0{width}X}".format((long(B_i, 16) ^ long(S_i, 16)), width=aes128_blk_len*2)
        C  += C_i
    # handling the last block
    if (last_bytes):
        counter = "{0:0{width}X}".format(msg_blk_len+1, width=msg_len_len*2)
        A_i = A_0_0 + nonce_padded + counter
        S_i = aes.encrypt(A_i.decode('hex')).encode('hex')
        B_i = "{0:0<{width}}".format(msg[(msg_blk_len)*aes128_blk_len*2:len(msg)], width=aes128_blk_len*2)
        C_i = "{0:0{width}X}".format((long(B_i, 16) ^ long(S_i, 16)), width=aes128_blk_len*2)
        C_i = C_i[:last_bytes*2]
        C  += C_i

    return C+U

def aes_ccm_dec(key, nonce, ctxt):
    aes128_blk_len = 128/8
    key_len = 128/8
    tag_len = 16
    nonce_len = 12
    assert len(nonce) <= nonce_len*2, "nonce must be of length less than or equal to 12 octets"
    assert len(key) == key_len*2, "key must be of length 16 octets"
    ciphertxt_len = len(ctxt)/2 - tag_len
    ciphertxt_len_len = 15 - nonce_len

    U = ctxt[ciphertxt_len*2:len(ctxt)]
    U = "{0:0<{width}}".format(U, width=aes128_blk_len*2)   # in case tag_len was != aes128_blk_len
    ciphertxt = ctxt[:ciphertxt_len*2]
    ciphertxt_blk_len = (len(ciphertxt)/2) / aes128_blk_len   # not counting the last non-full block, if any
    last_bytes        = (len(ciphertxt)/2) % aes128_blk_len

    aes = AES.new(key.decode('hex'), AES.MODE_ECB)

    # Decryption: AES-CTR(K, N, C)
    # Same key stream as Encryption, XORed with ciphertext
    A_0_0 ="{0:02X}".format(ciphertxt_len_len - 1)
    nonce_padded = "{0:0>{width}}".format(nonce, width=nonce_len*2)
    counter = "{0:0{width}X}".format(0, width=ciphertxt_len_len*2)
    A_0 = A_0_0 + nonce_padded + counter

    # Decrypting authentication tag:
    # First block of key stream is XORed with the encrypted tag, U, the last blob of the ciphertext
    S_0 = aes.encrypt(A_0.decode('hex')).encode('hex')
    T = "{0:0{width}X}".format((long(U, 16) ^ long(S_0, 16)), width=aes128_blk_len*2)
    T = T[:tag_len*2]

    # Decrypting ciphertext
    P = ""  # P: plaintext that should be the same as B1, B2, ...
    for i in range(1, ciphertxt_blk_len+1):
        counter = "{0:0{width}X}".format(i, width=ciphertxt_len_len*2)
        A_i = A_0_0 + nonce_padded + counter
        S_i = aes.encrypt(A_i.decode('hex')).encode('hex')
        C_i = ciphertxt[(i-1)*aes128_blk_len*2:i*aes128_blk_len*2]
        P_i = "{0:0{width}X}".format((long(C_i, 16) ^ long(S_i, 16)), width=aes128_blk_len*2)
        P  += P_i
    # handling the last block
    if (last_bytes):
        counter = "{0:0{width}X}".format(ciphertxt_blk_len+1, width=ciphertxt_len_len*2)
        A_i = A_0_0 + nonce_padded + counter
        S_i = aes.encrypt(A_i.decode('hex')).encode('hex')
        C_i = "{0:0<{width}}".format(ciphertxt[(ciphertxt_blk_len)*aes128_blk_len*2:len(ciphertxt)], width=aes128_blk_len*2)
        P_i = "{0:0{width}X}".format((long(C_i, 16) ^ long(S_i, 16)), width=aes128_blk_len*2)
        P_i = P_i[:last_bytes*2]
        P  += P_i

    # Authentication: AES-CBC-MAC(K, N, C)
    # Computed in the same way as in Encryption above with P as input (here B_i = P_i)
    B_0_0 ="{0:02X}".format( (((tag_len - 2)/2) << 3) | (ciphertxt_len_len - 1) )
    ciphertxt_len = "{0:0{width}X}".format(len(ciphertxt)/2, width=ciphertxt_len_len*2)
    B_0 = B_0_0 + nonce_padded + ciphertxt_len

    X = aes.encrypt(B_0.decode('hex')).encode('hex')
    for i in range(1, ciphertxt_blk_len+1):
        B_i = P[(i-1)*aes128_blk_len*2:i*aes128_blk_len*2]
        xor_out = "{0:0{width}X}".format((long(B_i, 16) ^ long(X, 16)), width=aes128_blk_len*2)
        X = aes.encrypt(xor_out.decode('hex')).encode('hex')

    # handling the last block
    if (last_bytes):
        B_i = "{0:0<{width}}".format(P[(ciphertxt_blk_len)*aes128_blk_len*2:len(ciphertxt)], width=aes128_blk_len*2)
        xor_out = "{0:0{width}X}".format((long(B_i, 16) ^ long(X, 16)), width=aes128_blk_len*2)
        X = aes.encrypt(xor_out.decode('hex')).encode('hex')

    if (T.upper() != X[:tag_len*2].upper()):
        return "-1"
    
    return P


key1 = "E58D5C8F8C9ED9785679E08ABC7C8116"
nonce1 = "A9F593C09EAEEA8BF0C1CF6A"
pt11 = "0653B5714D1357F4995BDDACBE10873951A1EBA663718D1AF35D2F0D52C79DE49BE622C4A6D90647BA2B004C3E8AE422FD27063AFA19AD883DCCBD97D98B8B0461B5671E75F19701C24042B8D3AF79B9FF62BC448EF9440B1EA3F7E5C0F4BFEFE3E326E62D5EE4CB4B4CFFF30AD5F49A7981ABF71617245B96E522E1ADD78A"
pt12 = "ACA650CCCCDA604E16A8B54A3335E0BC2FD9444F33E3D9B82AFE6F445357634974F0F1728CF113452321CBE5858304B01D4A14AE7F3B45980EE8033AD2A8599B78C29494C9E5F8945A8CADE3EB5A30D156C0D83271626DADDB650954093443FBAC9701C02E5A973F39C2E1761A4B48C764BF6DB215A54B285A06ECA3AF0A83F7"
pt13 = "D1AA8BBC04DFC92FFE2CB7748E70B02F5A91DA14781223A712D44C4BA14A1C78EB02387FE73FDCBCA8447056ACAA9B5F94D5208972B706DF9FC4C803EABB2BC58C3D8DF4AC496C34CB6BAB939478CB417995B2314DAF7AF3F4C8A8D5D57A03F0EB2B7BBD2D16BABBF22C5B1EEBFF72C7DD4F912D5821F9A6BFA2D063CE6F6648DF"

key2 = "B8453A728060F8D517BACEED3829F4D9"
nonce2 = "CFBCE69C884D5BABBBAAF9A3"
pt21 = "F7629B73DAE85A9BCA45C42EB7FC1818DC74A60E13AE65A043E24B5A4D3AE04C273E7D6F42710F2D223D09EB7C1315718A5A1293D482E4C45C3E852E5106AAD7B695A02C4854801A5EFE937A6540BCE8734E8141558C3433B1D4C733DC5EF9C47B5279AA46EE3D8BD33B0950BE5C9EBDF18BCF069B6DAF82FF1186912F0ABA"
pt22 = "29B4013F552FBCE993544CC6605CB05C62A7894C4C99E6A12C5F9F2EE4DFBEBAD70CDD0893542240F28BB5FBB9090332ED110ABFAE6C4C6460D916F8994136575B5A6FD8DB605FDF14CB81977AFF7F99B5272580BF220133C691B09BADC4D1FE7125FD17FDBFC103E3F00A4D8E5A6F1E3D3AF2A908535DE858E1CCD3DB4D1835"
pt23 = "1D76BDF0626A7134BEB28A90D54ED7796C4C9535465C090C4B583A8CD40EF0A3864E7C07CCAED140DF6B9D73234E652F8FF425FC206F63DFAB7DCDBBBE30411A14695E72A2BD8C4BFB1D6991DB4F99EEA7435E55261E37FDF57CE79DF725C810192F5E6E0331ED62EB8A72C5B9DA6DFD9748B3D168A69BAB33319EFD1E84EF2570"

print("""
Test vectors for AES-CCM-128 for 1609.2 v3
==========================================
It is based on NIST SP 800-38C (and RFC 3610) with the following:
- Adata = 0, i.e. no associated authenticated data
- t=16, i.e. tag length is 16 octets
- n=12, i.e. Nonce length is 12 octets
- q=3, i.e. the message length in octets is encoded in 3 octets

Inputs:
- key:       {octet string} AES-CCM key, K (hex encoded bytes)
- nonce:     {octet string} nonce, N (hex encoded bytes)
- plaintext: {octet string} plaintext to be encrypted and authenticated, P (hex encoded bytes)

Output:
ciphertext || tag = C || T {octet string}
""")

key_list = [key1, key1, key1, key2, key2, key2]
nnc_list = [nonce1, nonce1, nonce1, nonce2, nonce2, nonce2]
pt_list  = [pt11, pt12, pt13, pt21, pt22, pt23]
i = 1
for key, nonce, pt in zip(key_list, nnc_list, pt_list):
    c_t = aes_ccm_enc(key, nonce, pt)
    PT  = aes_ccm_dec(key, nonce, c_t)
    assert PT == pt, "decrypted ciphertext differs from plaintext"

    print("Test Vector #" + str(i) + ":")
    print("---------------")

    # print key
    print("K = 0x" + key)
    cArrayDef("", "key", long(key, 16), len(key)/2, radix_8, False); print(os.linesep)
    
    #print nonce
    print("N = 0x" + nonce)
    cArrayDef("", "nonce", long(nonce, 16), len(nonce)/2, radix_8, False); print(os.linesep)

    #print plaintext
    print("P = 0x" + pt)
    cArrayDef("", "pt", long(pt, 16), len(pt)/2, radix_8, False); print(os.linesep)

    #print ciphertext || tag
    print("C_T = 0x" + c_t)
    cArrayDef("", "c_t", long(c_t, 16), len(c_t)/2, radix_8, False); print(os.linesep)

    i += 1
