#!/usr/bin/env python3

import unittest
from implicit import *


class ImplicitCertUtilTests(unittest.TestCase):
    def setUp(self):
        self.genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

        self.tbsCert = "54686973206973206120746573742100"

        self.dCA = "97D1368E8C07A54F66C9DCE284BA76CAF4178206614F809A4EB43CB3106AA60E"
        self.QCAx = "3BB8FFD19B25EE1BB939CD4935FBFA8FBAADBA64843338A95595A70ED7479B70"
        self.QCAy = "EB60DDC790E3CB05E85225F636D8A7C20DF3A8135C4B2AE5396367B4E86077F8"
        self.QCA = ECPoint(int(self.QCAx, 16), int(self.QCAy, 16), secp256r1)

        self.RUx = "f45a99137b1bb2c150d6d8cf7292ca07da68c003daa766a9af7f67f5ee916828"
        self.RUy = "f6a25216f44cb64a96c229ae00b479857b3b81c1319fb2adf0e8db2681769729"
        self.RU = ECPoint(int(self.RUx, 16), int(self.RUy, 16), secp256r1)

        # Computed public key reconstruction point, given self.k
        self.k = "e2f9cbcec3f28f7dfbef044732c41119816c62909fb720b091fb8f380f1b70dc"
        self.PUx = "4a1890e30a584208dad3838d0c5cecb1ed6b01d48893c684c59908f5b38e3d82"
        self.PUy = "bae8fb2ef2dc080f248f44fcec458b1b35ecdc80f00c959292cbe21be2ff2ea2"
        self.PU = ECPoint(int(self.PUx, 16), int(self.PUy, 16), secp256r1)

        self.CertU = self.tbsCert + self.PU.output(compress=True)
        self.r = "1FA86893A1AABE8A79F63360F4B6D5617380B4D84B8C260DD8D3D64163C874FD"


    def test_compute_public_key_reconstruction_point_when_provided_k(self):
        self.assertEqual(int(self.k, 16) * self.genP256 + self.RU, self.PU)

    def test_CertU_equals_tbsData_and_public_key_reconstruction_point(self):
        self.assertEqual(self.CertU, self.tbsCert + self.PU.output(compress=True))

    def test_compute_private_key_reconstruction_point(self):
        e = sha256(binascii.unhexlify(self.CertU)).hexdigest()
        r_int = ((int(e, 16) // 2) * int(self.k, 16) + int(self.dCA, 16)) % self.genP256.ecc.n
        r = "{0:0>{width}X}".format(r_int, width=bitLen(genP256.ecc.n) * 2 // 8)
        self.assertEqual(r, self.r)

    def test_implicit_certificate_generation(self):
        PU, CertU, r = ImplicitCertUtil.gen_cert(self.tbsCert, self.RU, self.dCA, k=self.k)
        self.assertEqual(PU, self.PU)
        self.assertEqual(CertU, self.CertU)
        self.assertEqual(r, self.r)

    def test_reconstruct_private(self):
        kU = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"
        expect_dU = "C8599ECA52B58D691B2BB609CDB53DDD9F49C0D635AB652EC79C546914590274"
        dU = ImplicitCertUtil.reconstruct_private(kU, self.CertU, self.r)
        self.assertEqual(dU, expect_dU)

    def test_reconstructed_private_key_corresponds_to_reconstructed_public_key(self):
        kU = "1384C31D6982D52BCA3BED8A7E60F52FECDAB44E5C0EA166815A8159E09FFB42"
        dU = ImplicitCertUtil.reconstruct_private(kU, self.CertU, self.r)
        QU_ = int(dU, 16) * genP256
        QU = ImplicitCertUtil.reconstruct_public(self.CertU, self.QCA)
        self.assertEqual(QU_, QU)


if __name__ == '__main__':
    unittest.main()
