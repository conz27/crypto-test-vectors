#!/usr/bin/env python3

import unittest
from aesccm import *


class AESCCMTests(unittest.TestCase):
    """
    # Test vectors for AES-CCM-128 for 1609.2 v3
    # ==========================================
    # It is based on NIST SP 800-38C (and RFC 3610) with the following:
    # - Adata = 0, i.e. no associated authenticated data
    # - t=16, i.e. tag length is 16 octets
    # - n=12, i.e. Nonce length is 12 octets
    # - q=3, i.e. the message length in octets is encoded in 3 octets
    #
    # Inputs:
    # - key:       {octet string} AES-CCM key, K (hex encoded bytes)
    # - nonce:     {octet string} nonce, N (hex encoded bytes)
    # - plaintext: {octet string} plaintext to be encrypted and authenticated, P (hex encoded bytes)
    #
    # Output:
    # ciphertext || tag = C || T {octet string}
    # """
    def setUp(self):
        self.key1 = "E58D5C8F8C9ED9785679E08ABC7C8116"
        self.key2 = "B8453A728060F8D517BACEED3829F4D9"
        self.nonce1 = "A9F593C09EAEEA8BF0C1CF6A"
        self.nonce2 = "CFBCE69C884D5BABBBAAF9A3"

    def test_aesccm_key1_nonce1_pt1(self):
        pt1 = "0653B5714D1357F4995BDDACBE10873951A1EBA663718D1AF35D2F0D52C79DE49BE622C4A6D90647BA2B004C3E8AE422FD27063AFA19AD883DCCBD97D98B8B0461B5671E75F19701C24042B8D3AF79B9FF62BC448EF9440B1EA3F7E5C0F4BFEFE3E326E62D5EE4CB4B4CFFF30AD5F49A7981ABF71617245B96E522E1ADD78A"
        c_t = aes_ccm_enc(self.key1, self.nonce1, pt1)
        PT = aes_ccm_dec(self.key1, self.nonce1, c_t)
        self.assertEqual(pt1, PT)

    def test_aesccm_key1_nonce1_pt2(self):
        pt2 = "ACA650CCCCDA604E16A8B54A3335E0BC2FD9444F33E3D9B82AFE6F445357634974F0F1728CF113452321CBE5858304B01D4A14AE7F3B45980EE8033AD2A8599B78C29494C9E5F8945A8CADE3EB5A30D156C0D83271626DADDB650954093443FBAC9701C02E5A973F39C2E1761A4B48C764BF6DB215A54B285A06ECA3AF0A83F7"
        c_t = aes_ccm_enc(self.key1, self.nonce1, pt2)
        PT = aes_ccm_dec(self.key1, self.nonce1, c_t)
        self.assertEqual(pt2, PT)

    def test_aesccm_key1_nonce1_pt3(self):
        pt3 = "D1AA8BBC04DFC92FFE2CB7748E70B02F5A91DA14781223A712D44C4BA14A1C78EB02387FE73FDCBCA8447056ACAA9B5F94D5208972B706DF9FC4C803EABB2BC58C3D8DF4AC496C34CB6BAB939478CB417995B2314DAF7AF3F4C8A8D5D57A03F0EB2B7BBD2D16BABBF22C5B1EEBFF72C7DD4F912D5821F9A6BFA2D063CE6F6648DF"
        c_t = aes_ccm_enc(self.key1, self.nonce1, pt3)
        PT = aes_ccm_dec(self.key1, self.nonce1, c_t)
        self.assertEqual(pt3, PT)

    def test_aesccm_key2_nonce2_pt1(self):
        pt1 = "F7629B73DAE85A9BCA45C42EB7FC1818DC74A60E13AE65A043E24B5A4D3AE04C273E7D6F42710F2D223D09EB7C1315718A5A1293D482E4C45C3E852E5106AAD7B695A02C4854801A5EFE937A6540BCE8734E8141558C3433B1D4C733DC5EF9C47B5279AA46EE3D8BD33B0950BE5C9EBDF18BCF069B6DAF82FF1186912F0ABA"
        c_t = aes_ccm_enc(self.key2, self.nonce2, pt1)
        PT = aes_ccm_dec(self.key2, self.nonce2, c_t)
        self.assertEqual(pt1, PT)

    def test_aesccm_key2_nonce2_pt2(self):
        pt2 = "29B4013F552FBCE993544CC6605CB05C62A7894C4C99E6A12C5F9F2EE4DFBEBAD70CDD0893542240F28BB5FBB9090332ED110ABFAE6C4C6460D916F8994136575B5A6FD8DB605FDF14CB81977AFF7F99B5272580BF220133C691B09BADC4D1FE7125FD17FDBFC103E3F00A4D8E5A6F1E3D3AF2A908535DE858E1CCD3DB4D1835"
        c_t = aes_ccm_enc(self.key2, self.nonce2, pt2)
        PT = aes_ccm_dec(self.key2, self.nonce2, c_t)
        self.assertEqual(pt2, PT)

    def test_aesccm_key2_nonce2_pt3(self):
        pt3 = "1D76BDF0626A7134BEB28A90D54ED7796C4C9535465C090C4B583A8CD40EF0A3864E7C07CCAED140DF6B9D73234E652F8FF425FC206F63DFAB7DCDBBBE30411A14695E72A2BD8C4BFB1D6991DB4F99EEA7435E55261E37FDF57CE79DF725C810192F5E6E0331ED62EB8A72C5B9DA6DFD9748B3D168A69BAB33319EFD1E84EF2570"
        c_t = aes_ccm_enc(self.key2, self.nonce2, pt3)
        PT = aes_ccm_dec(self.key2, self.nonce2, c_t)
        self.assertEqual(pt3, PT)


if __name__ == '__main__':
    unittest.main()
