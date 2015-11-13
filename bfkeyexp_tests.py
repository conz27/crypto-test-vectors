#!/usr/bin/env python3

import unittest
from bfkeyexp import *


class BFKeyExpansionTests(unittest.TestCase):
    def setUp(self):
        # Test fixture is based on seed(333)
        seed(333)

        # Signing seed private key (256 bits)
        self.a = randint(1, genP256.ecc.n - 1)
        # Signing seed public key (2*256 bits)
        self.A = self.a * genP256
        self.h = randint(1, genP256.ecc.n - 1)
        self.H = self.h * genP256

        # AES keys (128 bits, randomly generated)
        self.ck = "{0:032X}".format(getrandbits(128))
        self.ek = "{0:032X}".format(getrandbits(128))

        # i (32 bits)
        self.i = randint(1, radix_32)
        # j (in range [1,20], padded to 32 bits)
        self.j = randint(1, 20)

        self.x_cert = (self.i * radix_32 + self.j) * radix_32
        self.x_enc = (((radix_32 - 1) * radix_32 + self.i) * radix_32 + self.j) * radix_32

    def test_fixture_must_use_seed_333(self):
        expected_i = "0x74F64E97"
        expected_j = "0x00000010"
        self.assertEqual(Hex(self.i, radix_32), expected_i)
        self.assertEqual(Hex(self.j, radix_32), expected_j)

    def test_f_k_int_x_cert(self):
        """f_k^{int}(x) = block1 || block2 || block3 (384 bits)"""
        expected = "75797E84044E4B418D69345841F3428A033CC53C8DC2C24FEF8123055354DE880B5D2555A596020E2186F4B4E45E9C88"
        result = BFKeyExpansion.f_k_int_x(self.ck, self.x_cert)
        self.assertEqual(result, expected)

    def test_f_k_x_cert(self):
        """f_k(x) = f_k^{int}(x) mod l, where l is the order of the group of points on the curve (256 bits)"""
        expected = "0xEA32856B63DE7B67F3BBD1421E6A7E9AFB8FAFB452CF110D3C0EA3760DB1961B"
        f_k_int_x_cert = BFKeyExpansion.f_k_int_x(self.ck, self.x_cert)
        result = int(f_k_int_x_cert, 16) % genP256.ecc.n
        self.assertEqual(Hex(result, radix_256), expected)

    def test_expanded_private_key(self):
        """a + f_k(x_cert) mod l: Expanded private key (256 bits)"""
        expected = "0x3273728E78E155125B4290AB1A1470AB75E4A728061E7C72A22365B09F582317"
        f_k_int_x_cert = BFKeyExpansion.f_k_int_x(self.ck, self.x_cert)
        f_k_x_cert = int(f_k_int_x_cert, 16) % genP256.ecc.n
        a_exp = (self.a + f_k_x_cert) % genP256.ecc.n
        self.assertEqual(Hex(a_exp, radix_256), expected)

    def test_expanding_certificate_pair_a_A(self):
        """H + f_k(x_enc)*G_P256 mod l: Expanded public key (256 bits)"""
        f_k_int_x_cert = BFKeyExpansion.f_k_int_x(self.ck, self.x_cert)
        f_k_x_cert = int(f_k_int_x_cert, 16) % genP256.ecc.n
        a_exp = (self.a + f_k_x_cert) % genP256.ecc.n
        expected = a_exp * genP256
        A_exp = self.A + f_k_x_cert * genP256
        self.assertEqual(A_exp, expected)

    def test_expanding_certificate_pair_h_H(self):
        """H + f_k(x_cert)*G_P256 mod l: Expanded public key (256 bits)"""
        f_k_int_x_cert = BFKeyExpansion.f_k_int_x(self.ek, self.x_cert)
        f_k_x_cert = int(f_k_int_x_cert, 16) % genP256.ecc.n
        h_exp = (self.h + f_k_x_cert) % genP256.ecc.n
        expected = h_exp * genP256
        H_exp = self.H + f_k_x_cert * genP256
        self.assertEqual(H_exp, expected)


if __name__ == '__main__':
    unittest.main()
