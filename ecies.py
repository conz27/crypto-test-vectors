from ecc import *
from ecdh import ecdh
from kdf import sha256_kdf
from mac1 import sha256_hmac

# Comment the following to obtain different values every time this script is run
seed(333)

radix_256 = 2 ** 256
radix_128 = 2 ** 128
radix_32 = 2 ** 32
radix_16 = 2 ** 16
radix_8 = 2 ** 8

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)


def ecies_enc(R, k, p1, v=None):
    """
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
    """

    k_len = 128 // 8
    p1_len = 256 // 8
    assert len(k) == k_len * 2, "input k must be of octet length: " + str(k_len)
    assert len(p1) == p1_len * 2, "input P1 must be of octet length: " + str(p1_len)
    assert R.is_on_curve(), "recipient's public key must be a point on the curve P-256"

    # Generate Sender's ephemeral key pair (v, V)
    if v is None:
        v_long = randint(1, genP256.ecc.n - 1)
        v = "{0:0>{width}X}".format(v_long, width=bitLen(genP256.ecc.n) * 2 // 8)
    else:
        v_long = int(v, 16)
    V = v_long * genP256

    # ECDH: compute a shared secret (sender's private key, recipient's public key)
    ss = ecdh(v, R)
    print("ss: ", ss)

    # Derive K1 and K2 with KDF
    K1_len = 128 // 8
    K2_len = 256 // 8
    dl = K1_len + K2_len
    K1_K2 = sha256_kdf(ss, p1, dl)

    # Encrypt k by XORing it with K1
    K1 = K1_K2[:K1_len * 2]
    enc_k = int(k, 16) ^ int(K1, 16)
    C = "{0:0>{width}X}".format(enc_k, width=k_len * 2)

    # Calculate MAC1 on C with key K2
    K2 = K1_K2[K1_len * 2:]
    T = sha256_hmac(K2, C)

    return V, C, T, v


def ecies_dec(V, C, T, r, p1):
    """
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
    """
    k_len = 128 // 8
    p1_len = 256 // 8
    assert len(C) == k_len * 2, "input C must be of octet length: " + str(k_len)
    assert len(p1) == p1_len * 2, "input P1 must be of octet length: " + str(p1_len)
    assert V.is_on_curve(), "sender's public key must be a point on the curve P-256"

    # ECDH: compute a shared secret (recipient's private key, sender's public key)
    ss = ecdh(r, V)

    # Derive K1 and K2 with KDF
    K1_len = 128 // 8
    K2_len = 256 // 8
    dl = K1_len + K2_len
    K1_K2 = sha256_kdf(ss, p1, dl)

    # Calculate MAC1 on C with key K2
    K2 = K1_K2[K1_len * 2:]
    T_dec = sha256_hmac(K2, C)

    if T_dec != T:
        return "-1"

    # Decrypt k by XORing C with K1
    K1 = K1_K2[:K1_len * 2]
    dec_C = int(C, 16) ^ int(K1, 16)
    k = "{0:0>{width}X}".format(dec_C, width=k_len * 2)

    return k
