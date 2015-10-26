#!/usr/bin/env python3

import unittest
from ecc import *


class ECCTests(unittest.TestCase):
    def setUp(self):
        self.genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)
        self.infP256 = ECPoint(0, 0, secp256r1)

    def test_add_and_double(self):
        """2*(2*P) = 2*P+P+P"""
        lhs = self.genP256 + self.genP256
        rhs = lhs
        lhs = lhs + lhs
        rhs = rhs + self.genP256
        rhs = rhs + self.genP256
        self.assertEqual(lhs, rhs)

    def test_two_times_p_equals_p_plus_p(self):
        """2*P = P+P"""
        lhs = 2 * self.genP256
        rhs = self.genP256 + self.genP256
        self.assertEqual(lhs, rhs)

    def test_four_times_p_equals_p_plus_p_plus_p_plus_p(self):
        """4*P = P+P+P+P"""
        lhs = 4 * self.genP256
        rhs = self.genP256 + self.genP256 + self.genP256 + self.genP256
        self.assertEqual(lhs, rhs)

    def test_three_times_three_times_p_equals_nine_times_p(self):
        """3*3*P = 9*P"""
        lhs = 3 * 3 * self.genP256
        rhs = 9 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_negative_operation_four_times_p_minus_p_equals_three_times_p(self):
        """4*P-P = 3*P"""
        lhs = 4 * self.genP256 - self.genP256
        rhs = 3 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_p_plus_zero_equals_p(self):
        """P+0 = P"""
        lhs = self.genP256 + self.infP256
        rhs = self.genP256
        self.assertEqual(lhs, rhs)

    def test_zero_times_p_equals_zero(self):
        """0*P = 0"""
        lhs = 0 * self.genP256
        rhs = self.infP256
        self.assertEqual(lhs, rhs)

    def test_one_times_p_equals_p(self):
        """1*P = P"""
        lhs = 1 * self.genP256
        rhs = self.genP256
        self.assertEqual(lhs, rhs)

    def test_n_times_p_equals_zero(self):
        """n*P = 0"""
        lhs = secp256r1.n * self.genP256
        rhs = self.infP256
        self.assertEqual(lhs, rhs)

    def test_n_minus_1_times_p_equals_negative_p(self):
        """(n-1)*P = -P"""
        lhs = (secp256r1.n - 1) * self.genP256
        rhs = -self.genP256
        self.assertEqual(lhs, rhs)

    def test_add_Jacobian_and_Affine(self):
        """add(Jacobian, Affine) - version 1"""
        lhs = ECPointJ(2 * self.genP256) + self.genP256
        lhs = ECPoint(lhs)
        rhs = 3 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_add2_Jacobian_and_Affine(self):
        """add2(Jacobian, Affine) - version 2"""
        lhs = ECPointJ(2 * self.genP256)
        lhs = lhs.add2(self.genP256)
        lhs = ECPoint(lhs)
        rhs = 3 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_add_Jacobian_and_Jacobian(self):
        """add(Jacobian, Jacobian)"""
        lhs = ECPointJ(self.genP256) + 2 * self.genP256
        lhs = lhs.addJ(ECPointJ(2 * self.genP256) + 2 * self.genP256)
        lhs = ECPoint(lhs)
        rhs = 7 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_double_Jacobian_with_add_Jacobian_and_Jacobian(self):
        """double(Jacobian) with add(Jacobian, Jacobian)"""
        lhs = ECPointJ(self.genP256) + 2 * self.genP256
        lhs = lhs.addJ(ECPointJ(self.genP256) + 2 * self.genP256)
        lhs = ECPoint(lhs)
        rhs = 6 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_add_Jacobian_and_Jacobian_equals_infinity(self):
        lhs = ECPointJ(self.genP256).double().addJ(ECPointJ(-2 * self.genP256))
        lhs = ECPoint(lhs)
        rhs = 0 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_double_Jacobian(self):
        """double(Jacobian) - version 1"""
        lhs = ECPointJ(self.genP256).double() + self.genP256
        lhs = ECPoint(lhs)
        rhs = 3 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_double_Jacobian_add_vs_double_Affine(self):
        """double(Jacobian) vs double(Affine) - version 1"""
        lhs = ECPointJ(self.genP256).double().add(2 * self.genP256)
        lhs = ECPoint(lhs)
        rhs = 4 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_double_Jacobian_add2_vs_double_Affine(self):
        """double(Jacobian) vs double(Affine) - version 2"""
        lhs = ECPointJ(self.genP256).double().add2(2 * self.genP256)
        lhs = ECPoint(lhs)
        rhs = 4 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_add_Jacobian_and_Affine_equals_infinity(self):
        """add(Jacobian, Affine) == infinity - version 1"""
        lhs = ECPointJ(self.genP256).double().add(-2 * self.genP256)
        lhs = ECPoint(lhs)
        rhs = 0 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_add2_Jacobian_and_Affine_equals_infinity(self):
        """add(Jacobian, Affine) == infinity - version 2"""
        lhs = ECPointJ(self.genP256).double().add2(-2 * self.genP256)
        lhs = ECPoint(lhs)
        rhs = 0 * self.genP256
        self.assertEqual(lhs, rhs)

    def test_mult_Jacobian_and_mult_Affine(self):
        # Jacobian
        k = randint(1, self.genP256.ecc.n - 1)
        lhs = ECPoint(self.genP256)
        lhs = self.genP256.multiplyJ(k)
        # Affine
        rhs = self.genP256.multiply(k)
        self.assertEqual(lhs, rhs)

    def test_octet_string_conversion_with_compression(self):
        k = randint(1, self.genP256.ecc.n - 1)
        orig = k * self.genP256
        os = orig.output()
        new = ECPoint(secp256r1, os)
        self.assertEqual(orig, new)

    def test_octet_string_conversion_without_compression(self):
        k = randint(1, self.genP256.ecc.n - 1)
        orig = k * self.genP256
        os = orig.output(False)
        new = ECPoint(secp256r1, os)
        self.assertEqual(orig, new)

    # ECDSA TESTS

    def test_ecdsa_sign_and_verify(self):
        digest = getrandbits(256)
        sec = randint(1, self.genP256.ecc.n - 1)
        pub = sec * self.genP256
        to_sign = ECDSA(256, pub, sec)
        to_verify = ECDSA(256, pub)
        (r, s) = to_sign.sign(digest)
        self.assertEqual(to_verify.verify(digest, r, s), True)

    def test_ecdsa_digest_from_nist_vector(self):
        msg = "Example of ECDSA with P-256".encode()
        dgst = int(sha256(msg).hexdigest(), 16)
        dgst_v = 0xA41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4
        self.assertEqual(dgst, dgst_v)

    def test_ecdsa_longterm_keypair(self):
        d_v = 0xC477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96
        Q_x_v = 0xB7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19
        Q_y_v = 0x3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09
        Q = d_v * self.genP256
        self.assertEqual(Q_x_v, Q.x)
        self.assertEqual(Q_y_v, Q.y)

    def test_ecdsa_ephemeral_point(self):
        k_v = 0x7A1A7E52797FC8CAAA435D2A4DACE39158504BF204FBE19F14DBB427FAEE50AE
        R = k_v * self.genP256
        R_x_v = 0x2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F
        self.assertEqual(R_x_v, R.x)

    def test_ecdsa_signature(self):
        r_v = 0x2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F
        s_v = 0xDC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1
        d_v = 0xC477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96
        k_v = 0x7A1A7E52797FC8CAAA435D2A4DACE39158504BF204FBE19F14DBB427FAEE50AE
        dgst_v = 0xA41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4
        Q = d_v * self.genP256
        to_sign = ECDSA(256, Q, d_v)
        (r, s) = to_sign.sign_k(k_v, dgst_v)
        self.assertEqual(r_v, r)
        self.assertEqual(s_v, s)

if __name__ == '__main__':
    unittest.main()
