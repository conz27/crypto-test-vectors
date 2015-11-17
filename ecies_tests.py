#!/usr/bin/env python3

import unittest
from ecies import *


class ECIESTests(unittest.TestCase):
    """
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
    """

    def test_ecies_vector_one(self):
        k1 = "9169155B08B07674CBADF75FB46A7B0D"
        p11 = "A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9"
        r1 = "060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085"
        Rx1 = "8C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11"
        Ry1 = "1270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E"

        R = ECPoint(int(Rx1, 16), int(Ry1, 16), secp256r1)
        V, C, T, v = ecies_enc(R, k1, p11, v=None)
        k_dec = ecies_dec(V, C, T, r1, p11)
        self.assertEqual(k_dec, k1)

    def test_ecies_vector_two(self):
        k2 = "687E9757DEBFD87B0C267330C183C7B6"
        p12 = "05BED5F867B89F30FE5552DF414B65B9DD4073FC385D14921C641A145AA12051"
        r2 = "DA5E1D853FCC5D0C162A245B9F29D38EB6059F0DB172FB7FDA6663B925E8C744"
        Rx2 = "8008B06FC4C9F9856048DA186E7DC390963D6A424E80B274FB75D12188D7D73F"
        Ry2 = "2774FB9600F27D7B3BBB2F7FCD8D2C96D4619EF9B4692C6A7C5733B5BAC8B27D"

        R = ECPoint(int(Rx2, 16), int(Ry2, 16), secp256r1)
        V, C, T, v = ecies_enc(R, k2, p12, v=None)
        k_dec = ecies_dec(V, C, T, r2, p12)
        self.assertEqual(k_dec, k2)

    def test_ecies_vector_one_with_ephemeral(self):
        v = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"
        k1 = "9169155B08B07674CBADF75FB46A7B0D"
        p11 = "A6B7B52554B4203F7E3ACFDB3A3ED8674EE086CE5906A7CAC2F8A398306D3BE9"
        r1 = "060E41440A4E35154CA0EFCB52412145836AD032833E6BC781E533BF14851085"
        Rx1 = "8C5E20FE31935F6FA682A1F6D46E4468534FFEA1A698B14B0B12513EED8DEB11"
        Ry1 = "1270FEC2427E6A154DFCAE3368584396C8251A04E2AE7D87B016FF65D22D6F9E"

        R = ECPoint(int(Rx1, 16), int(Ry1, 16), secp256r1)
        V, C, T, v = ecies_enc(R, k1, p11, v=v)
        k_dec = ecies_dec(V, C, T, r1, p11)
        self.assertEqual(k_dec, k1)

    def test_ecies_vector_two_with_ephemeral(self):
        v = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"
        k2 = "687E9757DEBFD87B0C267330C183C7B6"
        p12 = "05BED5F867B89F30FE5552DF414B65B9DD4073FC385D14921C641A145AA12051"
        r2 = "DA5E1D853FCC5D0C162A245B9F29D38EB6059F0DB172FB7FDA6663B925E8C744"
        Rx2 = "8008B06FC4C9F9856048DA186E7DC390963D6A424E80B274FB75D12188D7D73F"
        Ry2 = "2774FB9600F27D7B3BBB2F7FCD8D2C96D4619EF9B4692C6A7C5733B5BAC8B27D"

        R = ECPoint(int(Rx2, 16), int(Ry2, 16), secp256r1)
        V, C, T, v = ecies_enc(R, k2, p12, v=v)
        k_dec = ecies_dec(V, C, T, r2, p12)
        self.assertEqual(k_dec, k2)


if __name__ == '__main__':
    unittest.main()
