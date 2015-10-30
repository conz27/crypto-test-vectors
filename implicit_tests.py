#!/usr/bin/env python3

import unittest
from implicit import *


class ImplicitTests(unittest.TestCase):
    def setUp(self):
        self.genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)
        self.tbsCert = "54686973206973206120746573742100"
        self.k = "e2f9cbcec3f28f7dfbef044732c41119816c62909fb720b091fb8f380f1b70dc"
        self.RUx = "f45a99137b1bb2c150d6d8cf7292ca07da68c003daa766a9af7f67f5ee916828"
        self.RUy = "f6a25216f44cb64a96c229ae00b479857b3b81c1319fb2adf0e8db2681769729"
        self.RU = ECPoint(int(self.RUx, 16), int(self.RUy, 16), secp256r1)
        self.PUx = "4a1890e30a584208dad3838d0c5cecb1ed6b01d48893c684c59908f5b38e3d82"
        self.PUy = "bae8fb2ef2dc080f248f44fcec458b1b35ecdc80f00c959292cbe21be2ff2ea2"
        self.PU = ECPoint(int(self.PUx, 16), int(self.PUy, 16), secp256r1)


    def test_compute_public_key_reconstruction_point_when_provided_k(self):
        self.assertEqual(int(k, 16) * self.genP256 + self.RU, self.PU)

    def test_CertU_equals_tbsData_and_public_key_reconstruction_point(self):
        self.assertEqual(CertU, self.tbsCert + self.PU.output(compress=True))



if __name__ == '__main__':
    unittest.main()
