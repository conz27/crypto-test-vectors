#!/usr/bin/env python3

import unittest

from glv import *


class GroupLinkageValuesTests(unittest.TestCase):
    """
    Test vectors for Group Linkage Values glv(i,j)
    for i = {0,1} and j randomly chosen 32-bit value for test purposes
    ==================================================================

    Note: the argument k is not included in the notation of gplv1(i,j,k), gs1(i,k),
        gplv2(i,j,k), gs2(i,k) and glv(i,j,k) below
        as it is not included in their computation
    """
    def setUp(self):
        # Changing seed will break tests.
        seed(333)
        self.la_id1 = getrandbits(16)  # LA1 ID (16 bits)
        self.la_id2 = getrandbits(16)  # LA2 ID (16 bits)
        self.k = getrandbits(16)  # Group Chain Identifier (32 bits)
        self.ik = "{0:032X}".format(getrandbits(128))  # Indices Key; shared by LA1 & LA2 (128 bits)

    def test_la_ids_are_expected_values_given_seed_333(self):
        self.assertEqual(self.la_id1, 36361)
        self.assertEqual(self.la_id2, 22990)

    def test_vector_i_is_zero_and_j_is_random_32bit_value(self):
        # j (32 bits)
        j = getrandbits(32)  # 1212214562

        # LA1
        gls1_0 = genls(1, 0, None, None, prefix="gs")
        gplv1_0_j = genplv(1, 0, self.la_id1, gls1_0, j, prefix="gplv", keyname="gs")

        # LA2
        gls2_0 = genls(2, 0, None, None, prefix="gs")
        gplv2_0_j = genplv(2, 0, self.la_id2, gls2_0, j, prefix="gplv", keyname="gs")

        # glv(0,j)
        lv_0_j = genlv(0, gplv1_0_j, gplv2_0_j, "g")

        # ei(j,k)
        ei_j_k = genei(self.ik, self.k, j)

        self.assertEqual(gls1_0, "6B71A7EB5755F16E89981D2189A6DAEA")
        self.assertEqual(gplv1_0_j, 1059399705933500553190)
        self.assertEqual(gls2_0, "CC4DB977F595AD233F0F4E65408D9A9C")
        self.assertEqual(gplv2_0_j, 1765835159798112979434)
        self.assertEqual(lv_0_j, 1897131607478641663500)
        self.assertEqual(ei_j_k, 2240451558015941930213588650038882535)


if __name__ == '__main__':
    unittest.main()
