import os

import binascii
from Crypto.Cipher import AES
from array import *

radix_256 = 2 ** 256
radix_128 = 2 ** 128
radix_32 = 2 ** 32
radix_16 = 2 ** 16
radix_8 = 2 ** 8


def aes_ccm_enc(key, nonce, msg):
    """
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
    """

    aes128_blk_len = 128 // 8
    key_len = 128 // 8
    tag_len = 16
    nonce_len = 12
    assert len(nonce) == nonce_len * 2, "nonce must be of length 12 octets"
    assert len(key) == key_len * 2, "key must be of length 16 octets"
    msg_len_len = 15 - nonce_len
    msg_blk_len = (len(msg) // 2) // aes128_blk_len  # not counting the last non-full block, if any
    last_bytes = (len(msg) // 2) % aes128_blk_len

    aes = AES.new(binascii.unhexlify(key), AES.MODE_ECB)

    # Authentication: AES-CBC-MAC(K, N, M)
    # Block B0

    #  L: #octets in length of message field
    #   The first block B_0 is formatted as follows, where the length of the message field
    #   is encoded in most-significant-byte-first order:
    #
    #      Octet Number   Contents
    #      ------------   ---------
    #      0              Flags
    #      1 ... 15-L     Nonce N
    #      16-L ... 15    length of message field
    #
    #   Within the first block B_0, the Flags field is formatted as follows:
    #
    #      Bit Number   Contents
    #      ----------   ----------------------
    #      7            Reserved (always zero)
    #      6            Adata
    #      5 ... 3      (#octets in authentication field - 2)/2
    #      2 ... 0      (#octest in length of message field -1)

    #         X_1     := E(K, B_0)
    #         X_{i+1} := E(K, X_i XOR B_i)
    #         T := first-M-bytes( X_n+1 )

    B_0_0 = "{0:02X}".format((((tag_len - 2) // 2) << 3) | (msg_len_len - 1))
    nonce_padded = "{0:0>{width}}".format(nonce, width=nonce_len * 2)
    msg_len = "{0:0>{width}X}".format(len(msg) // 2, width=msg_len_len * 2)
    B_0 = B_0_0 + nonce_padded + msg_len

    enc_X = aes.encrypt(binascii.unhexlify(B_0))
    X = binascii.hexlify(enc_X)
    for i in range(1, msg_blk_len + 1):
        B_i = msg[(i - 1) * aes128_blk_len * 2:i * aes128_blk_len * 2]
        xor_out = "{0:0{width}X}".format((int(B_i, 16) ^ int(X, 16)), width=aes128_blk_len * 2)
        enc_X = aes.encrypt(binascii.unhexlify(xor_out))
        X = binascii.hexlify(enc_X)

    # handling the last block
    if last_bytes:
        B_i = "{0:0<{width}}".format(msg[msg_blk_len * aes128_blk_len * 2:len(msg)], width=aes128_blk_len * 2)
        xor_out = "{0:0{width}X}".format((int(B_i, 16) ^ int(X, 16)), width=aes128_blk_len * 2)
        enc_X = aes.encrypt(binascii.unhexlify(xor_out))
        X = binascii.hexlify(enc_X)
        # T := X[:tag_len*2]
        # Authentication tag T is the same length as AES block here so no truncation needed
        # Final tag is encrypted and is calculated after the first encrypted block is calculated

        # Encryption: AES-CTR(K, N, M)
    #    key stream blocks:
    #      S_i := E( K, A_i )   for i=0, 1, 2, ...
    #    Ciphertext:
    #      C_i := B_i XOR S_i   for i=1,2,...
    #    Tag:
    #      U   := T XOR S_0     truncated to tag length
    #
    #   The values A_i are formatted as follows, where the Counter field i is
    #   encoded in most-significant-byte first order:
    #
    #      Octet Number   Contents
    #      ------------   ---------
    #      0              Flags
    #      1 ... 15-L     Nonce N
    #      16-L ... 15    Counter i
    #
    # Flags byte = (#octest in length of message field-1) = L-1

    A_0_0 = "{0:02X}".format(msg_len_len - 1)
    # nonce_padded as calculated above
    counter = "{0:0{width}X}".format(0, width=msg_len_len * 2)
    A_0 = A_0_0 + nonce_padded + counter

    enc_S_0 = aes.encrypt(binascii.unhexlify(A_0))
    S_0 = binascii.hexlify(enc_S_0)
    U = "{0:0{width}X}".format((int(X, 16) ^ int(S_0, 16)), width=aes128_blk_len * 2)
    U = U[:tag_len * 2]

    C = ""
    for i in range(1, msg_blk_len + 1):
        counter = "{0:0{width}X}".format(i, width=msg_len_len * 2)
        A_i = A_0_0 + nonce_padded + counter
        enc_S_i = aes.encrypt(binascii.unhexlify(A_i))
        S_i = binascii.hexlify(enc_S_i)
        B_i = msg[(i - 1) * aes128_blk_len * 2:i * aes128_blk_len * 2]
        C_i = "{0:0{width}X}".format((int(B_i, 16) ^ int(S_i, 16)), width=aes128_blk_len * 2)
        C += C_i
    # handling the last block
    if last_bytes:
        counter = "{0:0{width}X}".format(msg_blk_len + 1, width=msg_len_len * 2)
        A_i = A_0_0 + nonce_padded + counter
        enc_S_i = aes.encrypt(binascii.unhexlify(A_i))
        S_i = binascii.hexlify(enc_S_i)
        B_i = "{0:0<{width}}".format(msg[msg_blk_len * aes128_blk_len * 2:len(msg)], width=aes128_blk_len * 2)
        C_i = "{0:0{width}X}".format((int(B_i, 16) ^ int(S_i, 16)), width=aes128_blk_len * 2)
        C_i = C_i[:last_bytes * 2]
        C += C_i

    return C + U


def aes_ccm_dec(key, nonce, ctxt):
    aes128_blk_len = 128 // 8
    key_len = 128 // 8
    tag_len = 16
    nonce_len = 12
    assert len(nonce) <= nonce_len * 2, "nonce must be of length less than or equal to 12 octets"
    assert len(key) == key_len * 2, "key must be of length 16 octets"
    ciphertxt_len = len(ctxt) // 2 - tag_len
    ciphertxt_len_len = 15 - nonce_len

    U = ctxt[ciphertxt_len * 2:len(ctxt)]
    U = "{0:0<{width}}".format(U, width=aes128_blk_len * 2)  # in case tag_len was != aes128_blk_len
    ciphertxt = ctxt[:ciphertxt_len * 2]
    ciphertxt_blk_len = (len(ciphertxt) // 2) // aes128_blk_len  # not counting the last non-full block, if any
    last_bytes = (len(ciphertxt) // 2) % aes128_blk_len

    aes = AES.new(binascii.unhexlify(key), AES.MODE_ECB)

    # Decryption: AES-CTR(K, N, C)
    # Same key stream as Encryption, XORed with ciphertext
    A_0_0 = "{0:02X}".format(ciphertxt_len_len - 1)
    nonce_padded = "{0:0>{width}}".format(nonce, width=nonce_len * 2)
    counter = "{0:0{width}X}".format(0, width=ciphertxt_len_len * 2)
    A_0 = A_0_0 + nonce_padded + counter

    # Decrypting authentication tag:
    # First block of key stream is XORed with the encrypted tag, U, the last blob of the ciphertext
    enc_S_0 = aes.encrypt(binascii.unhexlify(A_0))
    S_0 = binascii.hexlify(enc_S_0)
    T = "{0:0{width}X}".format((int(U, 16) ^ int(S_0, 16)), width=aes128_blk_len * 2)
    T = T[:tag_len * 2]

    # Decrypting ciphertext
    P = ""  # P: plaintext that should be the same as B1, B2, ...
    for i in range(1, ciphertxt_blk_len + 1):
        counter = "{0:0{width}X}".format(i, width=ciphertxt_len_len * 2)
        A_i = A_0_0 + nonce_padded + counter
        # S_i = aes.encrypt(A_i.decode('hex')).encode('hex')
        enc_S_i = aes.encrypt(binascii.unhexlify(A_i))
        S_i = binascii.hexlify(enc_S_i).decode('utf-8')
        C_i = ciphertxt[(i - 1) * aes128_blk_len * 2:i * aes128_blk_len * 2]
        P_i = "{0:0{width}X}".format((int(C_i, 16) ^ int(S_i, 16)), width=aes128_blk_len * 2)
        P += P_i
    # handling the last block
    if last_bytes:
        counter = "{0:0{width}X}".format(ciphertxt_blk_len + 1, width=ciphertxt_len_len * 2)
        A_i = A_0_0 + nonce_padded + counter
        enc_S_i = aes.encrypt(binascii.unhexlify(A_i))
        S_i = binascii.hexlify(enc_S_i).decode('utf-8')
        C_i = "{0:0<{width}}".format(ciphertxt[ciphertxt_blk_len * aes128_blk_len * 2:len(ciphertxt)],
                                     width=aes128_blk_len * 2)
        P_i = "{0:0{width}X}".format((int(C_i, 16) ^ int(S_i, 16)), width=aes128_blk_len * 2)
        P_i = P_i[:last_bytes * 2]
        P += P_i

    # Authentication: AES-CBC-MAC(K, N, C)
    # Computed in the same way as in Encryption above with P as input (here B_i = P_i)
    B_0_0 = "{0:02X}".format((((tag_len - 2) // 2) << 3) | (ciphertxt_len_len - 1))
    ciphertxt_len = "{0:0{width}X}".format(len(ciphertxt) // 2, width=ciphertxt_len_len * 2)
    B_0 = B_0_0 + nonce_padded + ciphertxt_len

    enc_X = aes.encrypt(binascii.unhexlify(B_0))
    X = binascii.hexlify(enc_X).decode('utf-8')
    for i in range(1, ciphertxt_blk_len + 1):
        B_i = P[(i - 1) * aes128_blk_len * 2:i * aes128_blk_len * 2]
        xor_out = "{0:0{width}X}".format((int(B_i, 16) ^ int(X, 16)), width=aes128_blk_len * 2)
        enc_X = aes.encrypt(binascii.unhexlify(xor_out))
        X = binascii.hexlify(enc_X).decode('utf-8')

    # handling the last block
    if last_bytes:
        B_i = "{0:0<{width}}".format(P[ciphertxt_blk_len * aes128_blk_len * 2:len(ciphertxt)],
                                     width=aes128_blk_len * 2)
        xor_out = "{0:0{width}X}".format((int(B_i, 16) ^ int(X, 16)), width=aes128_blk_len * 2)
        enc_X = aes.encrypt(binascii.unhexlify(xor_out))
        X = binascii.hexlify(enc_X).decode('utf-8')

    if T.upper() != X[:tag_len * 2].upper():
        return "-1"

    return P
