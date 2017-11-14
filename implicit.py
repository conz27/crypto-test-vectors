from __future__ import print_function
import os
from hashlib import sha256

from arrays import *
from ecc import *

radix_256 = 2**256
radix_8 = 2**8

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

def implicitCertGen(tbsCert, RU, dCA, k=None):
    '''
    Implicit Certificate Generation as per SEC4 Sec 3.4

    Inputs:
    - tbsCert: {octet string} To-be-signed user's certificate data
    - RU:      {ec256 point}  User's certificate request public key
    - dCA:     {octet string} CA's private key
    [- k:      {octet string} CA's ephemeral key, should be randomly generated by the CA
                              but can be input to this function for test purposes]

    Outputs:
    - PU:      {ec256 point} User's public key reconstruction point
    - CertU:   {octet string} tbsCert || PU
               In this script, to illustrate the concept, PU is concatenated with tbsCert;
               it is somewhat similar to CertificateBase in 1609.2 (see 1609dot2-schema.asn)
               as the verifyKeyIndicator (which is PU) is the last value in the CertificateBase construct,
               but this should be checked as it depends on the ASN.1 encoding employed.
               Important Note:
               - In 1609.2 v3 d9 Sec.6.4.3,
                 H(CertU) = H (H (ToBeSignedCertificate) || H (Entirety of issuer cert) )
                 This was confirmed by William by email on Oct 29, 2015
               Therefore here H(CertU) = H(tbsCert || PU) is just for illustration purposes
    - r:       {octet string} private key reconstruction value
    [- k:      {octet string} CA's ephemeral key, should be kept secret
                              but is output from this function for test purposes]
    '''
    r_len = 256/8
    assert len(dCA) == r_len*2, "input dCA must be of octet length: " + str(r_len)
    assert RU.is_on_curve(), "User's request public key must be a point on the curve P-256"

    # Generate CA's ephemeral key pair
    if (k == None):
        k_long = randint(1, genP256.ecc.n-1)
        k = "{0:0>{width}X}".format(k_long, width=bitLen(genP256.ecc.n)*2/8)
    else:
        k_long = long(k, 16)
    kG = k_long*genP256

    # Compute User's public key reconstruction point, PU
    PU = RU + kG

    # Convert PU to an octet string (compressed point)
    PU_os = PU.output(compress=True)

    # CertU = tbsCert || PU (see note above)
    CertU = tbsCert + PU_os

    # e = leftmost floor(log_2 n) bits of SHA-256(CertU), i.e.
    # e = Shiftright(SHA-256(CertU)) by 1 bit
    e = sha256(CertU.decode('hex')).hexdigest()
    e_long = long(e, 16)/2

    r_long = (e_long * k_long + long(dCA, 16)) % genP256.ecc.n
    r = "{0:0>{width}X}".format(r_long, width=bitLen(genP256.ecc.n)*2/8)
    return PU, CertU, r, k

def reconstructPrivateKey(kU, CertU, r):
    '''
    Implicit Certificate Private Key Reconstruction as per SEC4 Sec. 3.6

    Inputs:
    - kU:    {octet string} User's certificate request private key, corresponding to RU
    - CertU: {octet string} tbsCert || PU (see note above)
    - r:     {octet string} private key reconstruction value

    Output:
    - dU: {octet string} User's (reconstructed) private key

    Note:
    In SEC 4 Sec. 3.6, QU, the User's private key is calculated as
    QU' = dU*G
    and is verified to be equal to QU calculated by reconstruction (see function below)
    This check is performed in the tests, outside this function.
    '''

    # e = leftmost floor(log_2 n) bits of SHA-256(CertU)
    e = sha256(CertU.decode('hex')).hexdigest()
    e_long = long(e, 16)/2

    # Compute U's private key
    # dU = (e * kU + r) mod n
    dU_long = (e_long * long(kU, 16) + long(r, 16)) % genP256.ecc.n
    dU = "{0:0>{width}X}".format(dU_long, width=bitLen(genP256.ecc.n)*2/8)

    return dU

def reconstructPublicKey(CertU, QCA):
    '''
    Implicit Certificate Public Key Reconstruction as per SEC4 Sec. 3.5
    Can be performed by any party.

    Inputs:
    - CertU: {octet string} tbsCert || PU (see note above)
    - QCA:   {ec256 point}  CA's public key

    Output:
    - QU: {ec256_point} User's (reconstructed) public key
    '''

    # extract PU,
    # in this script it's the last 33 bytes of CertU, an octet string of a compressed point
    PU_os = CertU[-33*2:]

    # convert PU_os to an ec256_point
    PU = ECPoint(secp256r1, PU_os)

    # e = leftmost floor(log_2 n) bits of SHA-256(CertU)
    # Read note above about what is actually the input to SHA-256
    e = sha256(CertU.decode('hex')).hexdigest()
    e_long = long(e, 16)/2

    # Compute U's public key
    QU = e_long*PU + QCA

    return QU

k =  "E2F9CBCEC3F28F7DFBEF044732C41119816C62909FB720B091FB8F380F1B70DC"
tbsCert = "54686973206973206120746573742100"
kU = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"
RUx = "F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828"
RUy = "F6A25216F44CB64A96C229AE00B479857B3B81C1319FB2ADF0E8DB2681769729"
dCA = "97D1368E8C07A54F66C9DCE284BA76CAF4178206614F809A4EB43CB3106AA60E"
QCAx = "3BB8FFD19B25EE1BB939CD4935FBFA8FBAADBA64843338A95595A70ED7479B70"
QCAy = "EB60DDC790E3CB05E85225F636D8A7C20DF3A8135C4B2AE5396367B4E86077F8"

print("""
Test vectors for Implicit Certificate Generation and Public/Private Keys Reconstruction
=======================================================================================
As per SEC4

Certificate Generation Inputs:
    - tbsCert: {octet string} To-be-signed user's certificate data
    - RU:      {ec256 point}  User's certificate request public key
    - dCA:     {octet string} CA's private key
    [- k:      {octet string} CA's ephemeral key, should be randomly generated by the CA
                              but can be input to this function for test purposes]

Certificate Generation Outputs:
    - PU:      {ec256 point} User's public key reconstruction point
    - CertU:   {octet string} tbsCert || PU
               In this script, to illustrate the concept, PU is concatenated with tbsCert;
               i.e., H(CertU) = H(tbsCert || PU) is just for illustration purposes
               Important Note:
               - In 1609.2 v3 d9 Sec.6.4.3,
                 H(CertU) = H (H (ToBeSignedCertificate) || H (Entirety of issuer cert) )
    - r:       {octet string} private key reconstruction value
    [- k:      {octet string} CA's ephemeral key, should be kept secret
                              but is output from this function for test purposes]
------------

Private Key Reconstruction Inputs:
    - kU:    {octet string} User's certificate request private key, corresponding to RU
    - CertU: {octet string} tbsCert || PU (see note above)
    - r:     {octet string} private key reconstruction value

Private Key Reconstruction Output:
    - dU:    {octet string} User's (reconstructed) private key
------------

Public Key Reconstruction Inputs:
    - CertU: {octet string} tbsCert || PU (see note above)
    - QCA:   {ec256 point}  CA's public key

Public Key Reconstruction Outputs:
    - QU:    {ec256_point} User's (reconstructed) public key
""")

k_list = [k, None]
RU = ECPoint(long(RUx, 16), long(RUy, 16), secp256r1)

i = 1
for k in k_list:
    PU, CertU, r, k = implicitCertGen(tbsCert, RU, dCA, k=k)
    dU = reconstructPrivateKey(kU, CertU, r)

    QCA = ECPoint(long(QCAx, 16), long(QCAy, 16), secp256r1)
    QU = reconstructPublicKey(CertU, QCA)

    QU_ = long(dU, 16)*genP256
    assert QU_ == QU, "Reconstructed private key does not correspond to reconstructed public key"

    print("Test Vector #" + str(i) + ":")
    print("===============")

    print("tbsCert is the bytes of the string \"This is a test!\":")
    print("tbsCert = 0x" + tbsCert)
    cArrayDef("", "tbsCert", long(tbsCert, 16), len(tbsCert)/2, radix_8, False); print(os.linesep)

    print("User's certificate request private key:")
    print("kU = 0x" + kU)
    cArrayDef("", "kU", long(kU, 16), len(kU)/2, radix_8, False); print(os.linesep)
    
    print("User's certificate request public key (x-coordinate):")
    print("RUx = 0x" + RUx)
    cArrayDef("", "RUx", long(RUx, 16), len(RUx)/2, radix_8, False); print(os.linesep)

    print("User's certificate request public key (y-coordinate):")
    print("RUy = 0x" + RUy)
    cArrayDef("", "RUy", long(RUy, 16), len(RUy)/2, radix_8, False); print(os.linesep)

    print("CA's private key:")
    print("dCA = 0x" + dCA)
    cArrayDef("", "dCA", long(dCA, 16), len(dCA)/2, radix_8, False); print(os.linesep)

    print("CA's public key (x-coordinate):")
    print("QCAx = 0x" + QCAx)
    cArrayDef("", "QCAx", long(QCAx, 16), len(QCAx)/2, radix_8, False); print(os.linesep)

    print("CA's public key (y-coordinate):")
    print("QCAy = 0x" + QCAy)
    cArrayDef("", "QCAy", long(QCAy, 16), len(QCAy)/2, radix_8, False); print(os.linesep)

    print("CA's ephemeral private key (should be chosen at random by CA for every cert request):")
    print("k = 0x" + k)
    cArrayDef("", "k", long(k, 16), len(k)/2, radix_8, False); print(os.linesep)
    
    print("User's public key reconstruction point (x-coordinate):")
    print("PUx = " + Hex(PU.x, radix_256))
    cArrayDef("", "PUx", PU.x, 256/8, radix_8, False); print(os.linesep)

    print("User's public key reconstruction point (y-coordinate):")
    print("PUy = " + Hex(PU.y, radix_256))
    cArrayDef("", "PUy", PU.y, 256/8, radix_8, False); print(os.linesep)

    print("User's CertU (encoded in this way for illustration purpose and testing only):")
    print("CertU = 0x" + CertU)
    cArrayDef("", "CertU", long(CertU, 16), len(CertU)/2, radix_8, False); print(os.linesep)
    
    print("User's private key reconstruction value:")
    print("r = 0x" + r)
    cArrayDef("", "r", long(r, 16), len(r)/2, radix_8, False); print(os.linesep)
        
    print("User's reconstructed private key:")
    print("dU = 0x" + dU)
    cArrayDef("", "dU", long(dU, 16), len(dU)/2, radix_8, False); print(os.linesep)
    
    print("User's reconstructed public key (x-coordinate):")
    print("QUx = " + Hex(QU.x, radix_256))
    cArrayDef("", "QUx", QU.x, 256/8, radix_8, False); print(os.linesep)

    print("User's reconstructed public key (y-coordinate):")
    print("QUy = " + Hex(QU.y, radix_256))
    cArrayDef("", "QUy", QU.y, 256/8, radix_8, False); print(os.linesep)

    i += 1
