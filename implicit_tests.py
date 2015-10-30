#!/usr/bin/env python3

import unittest
from implicit import *


class ImplicitTests(unittest.TestCase):
    def setUp(self):
        self.genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

    def test_compute_public_key_reconstruction_point_when_provided_k(self):
        k = "e2f9cbcec3f28f7dfbef044732c41119816c62909fb720b091fb8f380f1b70dc"
        RUx = "f45a99137b1bb2c150d6d8cf7292ca07da68c003daa766a9af7f67f5ee916828"
        RUy = "f6a25216f44cb64a96c229ae00b479857b3b81c1319fb2adf0e8db2681769729"
        RU = ECPoint(int(RUx, 16), int(RUy, 16), secp256r1)
        PUx = "4a1890e30a584208dad3838d0c5cecb1ed6b01d48893c684c59908f5b38e3d82"
        PUy = "bae8fb2ef2dc080f248f44fcec458b1b35ecdc80f00c959292cbe21be2ff2ea2"
        PU = ECPoint(int(PUx, 16), int(PUy, 16), secp256r1)
        self.assertEqual(int(k, 16) * self.genP256 + RU, PU)


if __name__ == '__main__':
    unittest.main()
