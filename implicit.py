from __future__ import print_function
import os
from hashlib import sha256

from array import *
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

    Outputs:
    - PU:      {ec256 point} public key reconstruction point
      CertU:   {octet string} tbsCert || PU
               In this script, to illustrate the concept, PU is concatenated with tbsCert;
               it may be the same in 1609.2 CertificateBase (see 1609dot2-schema.asn)
               as the verifyKeyIndicator (which is PU) is the last value in the CertificateBase construct,
               but this should be checked as it depends on the ASN.1 encoding employed.
               Note that tbsCert is more largely defined than toBeSigned in 1609.2, as it includes all
               what precedes PU in CertificateBase
    - r:       {octet string} private key reconstruction value
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

    # e = SHA-256(CertU)
    e = sha256(CertU.decode('hex')).hexdigest()
    e_long = long(e, 16)/2

    r_long = (e_long * k_long + long(dCA, 16)) % genP256.ecc.n
    r = "{0:0>{width}X}".format(r_long, width=bitLen(genP256.ecc.n)*2/8)
    return PU, CertU, r

k =  "E2F9CBCEC3F28F7DFBEF044732C41119816C62909FB720B091FB8F380F1B70DC"
tbsCert = "54686973206973206120746573742100"
RUx = "F45A99137B1BB2C150D6D8CF7292CA07DA68C003DAA766A9AF7F67F5EE916828"
RUy = "F6A25216F44CB64A96C229AE00B479857B3B81C1319FB2ADF0E8DB2681769729"
dCA = "97D1368E8C07A54F66C9DCE284BA76CAF4178206614F809A4EB43CB3106AA60E"

RU = ECPoint(long(RUx, 16), long(RUy, 16), secp256r1)
PU, CertU, r = implicitCertGen(tbsCert, RU, dCA, k=k)

print("PU =", PU)
print("CertU = " + CertU)
print("r = " + r)
