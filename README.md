Crypto Test Vectors
===================

This directory contains test vectors for the following functions as specified 
[here](http://wiki.campllc.org/display/SP/Modifications+to+Crypto+Primitives+v0.2-2015-08-18):

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

### Other files:
- radix.py:  
- array.py: utility scripts for printing the output  
- ecc.py: Elliptic Curve Cryptosystems core computations
