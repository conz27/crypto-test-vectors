Crypto Test Vectors
===================

This directory contains test vectors for the following functions as specified 
[here](https://wiki.campllc.org/display/SP/Modifications+to+Crypto+Primitives).

Additionally there are test vectors for crypto functions needed for encryption
and signing/verification.

All python scripts implement the corresponding functionality in order to depict
the mathematical and cryptographic calculations involved.

Linkage Values lv(i,j)
----------------------
- lv.txt: test vectors for i = {0,1} and j randomly chosen in [1,20]  
- lv.py : Python script that generates the test vectors

Group Linkage Values glv(i,j,k) and Encrypted Indices ei(j,k)
-------------------------------------------------------------
- glv.txt: test vectors for i = {0,1} and j randomly chosen 32-bit value  
- glv.py : Python script that generates the test vectors

Butterfly Expansion Function
----------------------------
- bfkeyexp.txt: test vectors for Butterfly Expansion Function for Certificate and
              Encryption key pairs  
- bfkeyexp.py : Python script that generates the test vectors

Key Derivation Function, KDF2 [IEEE-1363a, ANSI X9.63] with SHA-256
-------------------------------------------------------------------
- kdf.txt: ANSI X9.63 test vectors of KDF2 with SHA-256  
- kdf.py : Python script that implements KDF2 and tests it against the test
           vectors included

Message Authentication Code, MAC1 (HMAC)[IEEE-1363a, ANSI X9.71, RFC 2104, 4231] with SHA-256
---------------------------------------------------------------------------------------------
- mac1.txt: RFC 4231 test vectors of HMAC-SHA-256  
- mac1.py : Python script that implements HMAC-SHA-256 and tests it against the test
            vectors included

AES-CCM-128 Symmetric Authenticated Encryption [IEEE-1609.2, NIST SP 800-38C]
------------------------------------------------------------------------------
- aesccm.txt: test vectors for AES-CCM-128 Symmetric Authenticate Encryption
              based on NIST SP 800-38C (and RFC 3610) with parameters defined in IEEE-1609.2  
- aesccm.py : Python script that generates the test vectors

ECDH Key Agreement [SP800-56A Section 5.7.1.2]
----------------------------------------------
- ecdh.txt: test vectors for ECDH Key Agreement Scheme as per SP800-56A
            Section 5.7.1.2 using NIST test vectors  
- ecdh.py : Python script that implements ECDH for curve P-256 and tests it against the test
            vectors included

ECIES Public-Key Encryption [IEEE-1609.2]
------------------------------------------
- ecies.txt: test vectors for ECIES Encryption as per IEEE-1609.2,
             Used to wrap AES-CCM 128-bit keys  
- ecies.py : Python script that generates the test vectors

Implicit Certificate Generation and Public/Private Keys Reconstruction [SEC-4]
------------------------------------------------------------------------------
- implicit.txt: test vectors for generating implicit certificates and for
                reconstructing the corresponding private and public keys as per
                [SEC-4].  
- implicit.py : Python script that generates the test vectors

### Other files:
- radix.py:  
- array.py: utility scripts for printing the output  
- ecc.py: Elliptic Curve Cryptosystems core computations
