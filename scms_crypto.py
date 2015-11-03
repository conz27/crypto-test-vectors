import ctypes

from sys import platform as _platform
from ctypes import *

SHA256_BUFSIZE = 32  # bytes; 256-bit

if _platform == "darwin":
    # Dev
    lib = CDLL("lib/libmbedtls.dylib")
else:
    lib = CDLL("lib/libmbedtls.so")


class Crypto:
    """ mbedTLS Python Bindings
    """

    #####################################
    # NIST-COMPLIANT CTR_DRBG OPERATIONS
    #####################################

    @staticmethod
    def random(numbytes):
        """Generates a secure random from 1 to 1024 bytes.

        :param numbytes: numbers of bytes of randomness (1-1024 per call)
        :return: number of requested random bytes
        """
        if numbytes < 1:
            return None

        if numbytes > 1024:
            raise RuntimeError("Requested data cannot be larger than 1024 bytes.")

        rdm = lib.scms_random
        rdm.argtypes = [c_int]
        rdm.restype = c_char_p
        ret = rdm(numbytes)

        val = create_string_buffer(numbytes)
        ctypes.memmove(val, ret, numbytes)

        return val.raw

    ##################
    # HASH OPERATIONS
    ##################

    @staticmethod
    def mac1(buf, key):
        """ Generate SCMS Mac1 (HMAC-SHA256) from buffer and key

        :param buf: buffer of data
        :param key: HMAC key
        :return: SHA256 HMAC hash
        """
        mac1 = lib.scms_mac1
        mac1.argtypes = [c_void_p, c_size_t, c_char_p, c_size_t]
        mac1.restype = c_void_p
        ret = mac1(buf, len(buf), key, len(key))

        val = create_string_buffer(SHA256_BUFSIZE)
        ctypes.memmove(val, ret, SHA256_BUFSIZE)

        return val.raw

    @staticmethod
    def sha256(buf):
        """Generate SHA-256 hash from buffer

        :param buf: buffer of data
        :return: SHA-256 hash
        """
        sha256 = lib.scms_sha256
        sha256.argtypes = [c_void_p, c_size_t]
        sha256.restype = c_void_p
        ret = sha256(buf, len(buf))

        val = create_string_buffer(SHA256_BUFSIZE)
        ctypes.memmove(val, ret, SHA256_BUFSIZE)

        return val.raw

    #######################
    # EC CRYPTO OPERATIONS
    #######################

    @staticmethod
    def generate_ec_keypair():
        """Generates an ECC SECP256R1 keypair.

        :return: tuple containing public key and private key
        """
        ecdsa = lib.scms_ec_genkey
        ecdsa.restype = c_void_p

        ret = ecdsa()
        if ret is None:
            raise RuntimeError("scms_ec_genkey() failed: %d" % ret)

        pubkey_len = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(pubkey_len, ret, sizeof(c_size_t))

        int_publen = int.from_bytes(pubkey_len, byteorder='little')

        pubkey = create_string_buffer(int_publen)
        ctypes.memmove(pubkey, ret + sizeof(c_size_t), int_publen)

        privkey_len = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(privkey_len, ret + sizeof(c_size_t) + int_publen, sizeof(c_size_t))

        int_privlen = int.from_bytes(privkey_len, byteorder='little')

        privkey = create_string_buffer(int_privlen)
        ctypes.memmove(privkey, ret + sizeof(c_size_t) + int_publen + sizeof(c_size_t), int_privlen)

        return pubkey, privkey


    @staticmethod
    def ecp_get_private(key, isCompressed=True):
        """
        :param pkcs8_key: PKCS8 PEM-formatted key
        :return: raw EC private key
        """
        ec = lib.scms_get_private
        ec.argtypes = [c_char_p, c_int]
        ec.restype = c_void_p
        ret = ec(key, isCompressed)
        if ret is None:
            raise RuntimeError("scms_get_private() failed: %d" % ret)

        privkey_len = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(privkey_len, ret, sizeof(c_size_t))

        int_privlen = int.from_bytes(privkey_len, byteorder='little')

        privkey = create_string_buffer(int_privlen)
        ctypes.memmove(privkey, ret + sizeof(c_size_t), int_privlen)

        return privkey[1:33]
        # return privkey


    @staticmethod
    def ecp_get_public(key, isCompressed=True):
        """
        :param pkcs8_key: PKCS8 PEM-formatted key
        :return: raw EC public key
        """
        ec = lib.scms_get_public
        ec.argtypes = [c_char_p, c_int]
        ec.restype = c_void_p
        ret = ec(key, isCompressed)
        if ret is None:
            raise RuntimeError("scms_get_public() failed: %d" % ret)

        pubkey_len = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(pubkey_len, ret, sizeof(c_size_t))

        int_publen = int.from_bytes(pubkey_len, byteorder='little')

        pubkey = create_string_buffer(int_publen)
        ctypes.memmove(pubkey, ret + sizeof(c_size_t), int_publen)

        if isCompressed:
            x = pubkey[1:34]
            y = b''
        else:
            x = pubkey[1:33]
            y = pubkey[33:65]

        return x, y


    ###################
    # ECDSA OPERATIONS
    ###################

    @staticmethod
    def generate_ecdsa_keypair():
        """Generates a ECDSA SECP256R1 keypair.

        :return: tuple containing public key and private key
        """
        ecdsa = lib.scms_ec_raw_genkey
        ecdsa.restype = c_void_p

        ret = ecdsa()
        if ret is None:
            raise RuntimeError("scms_ec_raw_genkey() failed: %d" % ret)

        pubkey_len = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(pubkey_len, ret, sizeof(c_size_t))

        int_publen = int.from_bytes(pubkey_len, byteorder='little')

        pubkey = create_string_buffer(int_publen)
        ctypes.memmove(pubkey, ret + sizeof(c_size_t), int_publen)

        privkey_len = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(privkey_len, ret + sizeof(c_size_t) + int_publen, sizeof(c_size_t))

        int_privlen = int.from_bytes(privkey_len, byteorder='little')

        privkey = create_string_buffer(int_privlen)
        ctypes.memmove(privkey, ret + sizeof(c_size_t) + int_publen +
                       sizeof(c_size_t), int_privlen)

        return pubkey, privkey


    @staticmethod
    def ecdsa_sign(buf, privkey):
        """Signs a buffer using an ECC SECP256R1 private key.

        :param buf: buffer to sign
        :param privkey: ECC SECP256R1 private key
        :return: ECDSA signature representing the signed data
        """
        sign = lib.scms_ecdsa_sign
        sign.argtypes = [c_char_p, c_size_t, c_char_p]
        sign.restype = c_void_p
        ret = sign(buf, len(buf), privkey)
        if ret is None:
            raise RuntimeError("scms_ecc_sign() failed: %d" % ret)

        sig_len = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(sig_len, ret, sizeof(c_size_t))

        int_siglen = int.from_bytes(sig_len, byteorder='little')
        sig = create_string_buffer(int_siglen)
        ctypes.memmove(sig, ret + sizeof(c_size_t), int_siglen)

        return sig

    @staticmethod
    def ecdsa_decompose_sig(sig):
        r = sig[4:36]
        s = sig[-32:]

        return r, s

    @staticmethod
    def ecdsa_verify(buf, sig, pubkey):
        """ Verifies a buffer given an ECC SECP256R1 public key and signature.

        :param buf: buffer to verify
        :param sig: ECDSA signature generated from signing
        :param pubkey: ECC SECP256R1 public key
        :return: 0 on success (pass/fail)
        """
        verify = lib.scms_ecdsa_verify
        verify.argtypes = [c_char_p, c_size_t, c_char_p, c_size_t, c_char_p]
        ret = verify(buf, len(buf), sig, len(sig), pubkey)
        if ret != 0:
            raise RuntimeError("scms_ecc_verify() failed: %d" % ret)
        return ret

    ###################
    # ECIES OPERATIONS
    ###################

    @staticmethod
    def ecies_encrypt(msg, hmac_key, iv, sender_private, recipient_public):
        """ Performs ECIES encryption

        :param sender_private: Sender's private EC key
        :param recipient_public: Recipient's public EC key
        :return: tuple of ciphertext buffer and MAC tag
        """
        if len(iv) is not 12:
            raise RuntimeError("ccm_encrypt 'iv' must be 12 bytes.")

        encrypt = lib.scms_ecies_encrypt
        encrypt.argtypes = [c_void_p, c_size_t,
                            c_char_p, c_size_t,
                            c_char_p, c_char_p, c_char_p]
        encrypt.restype = c_void_p

        ret = encrypt(msg, len(msg), hmac_key, len(hmac_key), iv, sender_private, recipient_public)

        # Create a buffer to store the size of the ciphertext.
        olen = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(olen, ret, sizeof(c_size_t))

        # Convert the byte object to int
        int_olen = int.from_bytes(olen, byteorder='little')

        # Create buffer *exactly* large enough to hold the ciphertext
        buf = create_string_buffer(int_olen)
        ctypes.memmove(buf, ret + sizeof(c_size_t), int_olen)

        # Create buffer *exactly* large enough to hold the tag
        tag = create_string_buffer(16)
        ctypes.memmove(tag, ret + sizeof(c_size_t) + int_olen, 16)

        return buf.raw, tag.raw

    @staticmethod
    def ecies_decrypt(msg, hmac_key, iv, tag, recipient_private, sender_public):
        """ Performs ECIES decryption

        :param msg: msg to decrypt
        :param tag: MAC tag (generated during encryption, needs to be supplied for decrypt)
        :param iv: initialization vector (must be same as IV used for encrypt)
        :param recipient_private: Recipient's private EC key
        :param sender_public: Sender's public EC key
        :return: plaintext buffer
        """
        if len(iv) is not 12 or len(tag) is not 16:
            raise RuntimeError("ccm_decrypt 'iv' must be 12 bytes and 'tag' must be 16 bytes.")

        decrypt = lib.scms_ecies_decrypt
        decrypt.argtypes = [c_void_p, c_size_t,
                            c_char_p, c_size_t,
                            c_char_p, c_char_p,
                            c_char_p, c_char_p]
        decrypt.restype = c_void_p

        ret = decrypt(msg, len(msg), hmac_key, len(hmac_key), iv, tag, recipient_private, sender_public)

        # Create a buffer to store the size of the plaintext.
        olen = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(olen, ret, sizeof(c_size_t))

        # Convert the byte object to int
        int_olen = int.from_bytes(olen, byteorder='little')

        # Create a buffer *exactly* large enough to hold the plaintext.
        buf = create_string_buffer(int_olen)
        ctypes.memmove(buf, ret + sizeof(c_size_t), int_olen)

        return buf.raw

    ########################################
    # SYMMETRIC CRYPTO OPERATIONS (AES-CCM)
    ########################################

    @staticmethod
    def ccm_encrypt(buffer, key, iv=b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21'):
        """Performs AES-128-CCM encryption

        :param buffer: buffer to encrypt
        :param key: 128-bit AES key
        :param iv: initialization vector (must be same as IV used for decrypt)
        :return: tuple of ciphertext buffer and MAC tag
        """
        if len(iv) is not 12:
            raise RuntimeError("ccm_encrypt 'iv' must be 12 bytes.")

        encrypt = lib.scms_ccm_encrypt
        encrypt.argtypes = [c_void_p, c_size_t, c_char_p]
        encrypt.restype = c_void_p

        ret = encrypt(buffer, len(buffer), key, iv)

        # Create a buffer to store the size of the ciphertext.
        olen = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(olen, ret, sizeof(c_size_t))

        # Convert the byte object to int
        int_olen = int.from_bytes(olen, byteorder='little')

        # Create buffer *exactly* large enough to hold the ciphertext
        buf = create_string_buffer(int_olen)
        ctypes.memmove(buf, ret + sizeof(c_size_t), int_olen)

        # Create buffer *exactly* large enough to hold the tag
        tag = create_string_buffer(16)
        ctypes.memmove(tag, ret + sizeof(c_size_t) + int_olen, 16)

        return buf.raw, tag.raw

    @staticmethod
    def ccm_decrypt(buffer, key, tag, iv=b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21'):
        """ Performs AES-128-CCM decryption

        :param buffer: buffer to decrypt
        :param key: 128-bit AES key
        :param tag: MAC tag (generated during encryption, needs to be supplied for decrypt)
        :param iv: initialization vector (must be same as IV used for encrypt)
        :return: plaintext buffer
        """
        if len(iv) is not 12 or len(tag) is not 16:
            raise RuntimeError("ccm_decrypt 'iv' must be 12 bytes and 'tag' must be 16 bytes.")

        decrypt = lib.scms_ccm_decrypt
        decrypt.argtypes = [c_void_p, c_size_t, c_char_p, c_char_p, c_char_p]
        decrypt.restype = c_void_p

        ret = decrypt(buffer, len(buffer), key, tag, iv)

        # Create a buffer to store the size of the plaintext.
        olen = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(olen, ret, sizeof(c_size_t))

        # Convert the byte object to int
        int_olen = int.from_bytes(olen, byteorder='little')

        # Create a buffer *exactly* large enough to hold the plaintext.
        buf = create_string_buffer(int_olen)
        ctypes.memmove(buf, ret + sizeof(c_size_t), int_olen)

        return buf.raw

    #####################
    # TLS 1.2 OPERATIONS
    #####################

    @staticmethod
    def tls_client_init(socket_fd, server_cert, client_cert, client_key):
        """Initializes TLSv1.2 connection

        :param socket_fd: Python socket()'s file descriptor
        :param server_cert: PEM-encoded server certificate
        :param client_cert: PEM-encoded client certificate
        :param client_key: client private key
        :return: 0 on success
        """
        tls = lib.scms_tls_client_init
        tls.argtypes = [c_int, c_char_p, c_char_p, c_char_p]
        tls.restype = c_int
        ret = tls(socket_fd, server_cert, client_cert, client_key)
        if ret != 0:
            raise RuntimeError("scms_tls_client_init() failed: %d" % ret)
        return ret

    @staticmethod
    def tls_server_init(socket_fd, server_cert, server_key, server_crl):
        """Initializes TLSv1.2 server-mode connection

        :param socket_fd: Python socket()'s file descriptor
        :param server_cert: PEM-encoded server certificate
        :param server_key: server private key
        :return: 0 on success
        """
        tls = lib.scms_tls_server_init
        tls.argtypes = [c_int, c_char_p, c_char_p, c_char_p]
        tls.restype = c_int
        ret = tls(socket_fd, server_cert, server_key, server_crl)
        if ret != 0:
            raise RuntimeError("scms_tls_server_init() failed: %d" % ret)
        return ret

    @staticmethod
    def tls_handshake():
        """Initiates TLS handshake

        :return: 0 on success
        """
        handshake = lib.scms_tls_handshake
        ret = handshake()
        if ret != 0:
            raise RuntimeError("scms_tls_handshake() failed: %d" % ret)
        return ret

    @staticmethod
    def tls_verify():
        """Performs certificate & hostname verification

        This is called to ensure that only our TLS server will be communicated with, and not arbitrary TLS servers.
        We explicitly pass Hostname/certificate mismatch, but we disallow connection to services using either a
        revoked, expired and unknown certificate.

        :return: 0 on success
        """
        verify = lib.scms_tls_verify
        ret = verify()
        if ret != 0:
            raise RuntimeError("scms_tls_verify() failed: %d" % ret)
        return ret

    @staticmethod
    def tls_read(num_bytes):
        """Reads N-bytes off TLS stream

        :param num_bytes: number of desired bytes to read
        :return: bytes read from TLS stream
        """
        ssl = lib.scms_tls_read
        ssl.argtypes = [c_size_t]
        ssl.restype = c_void_p
        ret = ssl(num_bytes)
        if ret is None:
            return None

        buf_len = create_string_buffer(4)
        ctypes.memmove(buf_len, ret, 4)
        int_olen = int.from_bytes(buf_len, byteorder='little')
        buf = create_string_buffer(int_olen)
        ctypes.memmove(buf, ret + 4, int_olen)
        return buf.raw

    @staticmethod
    def tls_write(buf):
        """Write buffer to TLS stream

        There is a 16384 byte constraint per spec. A suggested way to call this from
        Python might be..

        def chunks(buf, n):
            for i in range(0, len(buf), n):
                yield buf[i:i+n]

        and called like this...

        for chunk in chunks(data, 16384):
            ret = Crypto.tls_write(chunk)

        :param buf: buffer to write
        :return: number of bytes written
        """
        ssl = lib.scms_tls_write
        ssl.argtypes = [c_char_p, c_size_t]
        ssl.restype = c_int
        ret = ssl(buf, len(buf))
        if ret <= 0:
            # We probably don't want to invoke runtime errors in HB, instead return
            # an error code to BE and resume HB> command prompt operations.
            raise RuntimeError("scms_tls_write() failed: %d" % ret)
        return ret

    @staticmethod
    def tls_close():
        """Closes a TLS connection without notification (error case)

        :return: 0 on success
        """
        close = lib.scms_tls_close
        ret = close()
        if ret != 0:
            raise RuntimeError("scms_tls_close() failed: %d" % ret)
        return ret

    @staticmethod
    def tls_close_notify():
        """Notifies the server and closes the clients connection.

        Note: This function internally calls tls_close() to clean up after notification.

        :return: 0 on success
        """
        close = lib.scms_tls_close_notify
        ret = close()
        return ret

    #########################
    # CERTIFICATE OPERATIONS
    #########################

    @staticmethod
    def generate_csr(subject_name, private_key):
        """Generates an X.509 Certificate Signing Request

        :param subject_name: DN-string
        :param private_key: EC private key
        :return:
        """
        csr = lib.scms_cert_gencsr
        csr.argtypes = [c_char_p, c_char_p]
        csr.restype = c_void_p
        ret = csr(subject_name, private_key)
        if ret is None:
            raise RuntimeError("scms_cert_gencsr() failed: %d" % ret)

        # Create a buffer to store the size of the CSR
        olen = create_string_buffer(sizeof(c_size_t))
        ctypes.memmove(olen, ret, sizeof(c_size_t))

        # Convert the byte object to int
        int_olen = int.from_bytes(olen, byteorder='little')

        # Create a buffer *exactly* large enough to hold the CSR.
        buf = create_string_buffer(int_olen)
        ctypes.memmove(buf, ret + sizeof(c_size_t), int_olen)

        return buf.raw



