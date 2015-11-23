#!/usr/bin/env python3

import unittest

from lv import *


class LinkageValuesTests(unittest.TestCase):
    """
    Test vectors for Linkage Values lv(i,j)
    for i = {0,1} and j randomly chosen in [1,20] for test purposes
    ===============================================================
    """
    def setUp(self):
        # Changing seed will break tests.
        seed(333)
        self.la_id1 = getrandbits(16)  # "36361"
        self.la_id2 = getrandbits(16)  # "22990"

    def test_la_ids_are_expected_values_given_seed_333(self):
        self.assertEqual(self.la_id1, 36361)
        self.assertEqual(self.la_id2, 22990)

    def test_vector_i_is_zero_and_j_is_random_from_one_to_twenty(self):
        # j (in range [1,20], padded to 32 bits)
        j = randint(1, 20)

        # LA1
        ls1_0 = genls(1, 0, None, None)
        plv1_0_j = genplv(1, 0, self.la_id1, ls1_0, j)

        # LA2
        ls2_0 = genls(2, 0, None, None)
        plv2_0_j = genplv(2, 0, self.la_id2, ls2_0, j)

        # lv (0,j)
        lv_0_j = genlv(0, plv1_0_j, plv2_0_j)

        self.assertEqual(ls1_0, "1502D9AB6786BF68FBA9F210373BF221")
        self.assertEqual(plv1_0_j, 4473001393966194589182)
        self.assertEqual(ls2_0, "5755F16E89981D2189A6DAEA4840ED22")
        self.assertEqual(plv2_0_j, 245336622344210819588)
        self.assertEqual(lv_0_j, 4707948203137323915258)

    def test_vector_is_is_one_and_j_is_random_from_one_to_twenty(self):
        # Generated from first test.
        ls1_0 = "1502D9AB6786BF68FBA9F210373BF221"
        ls2_0 = "5755F16E89981D2189A6DAEA4840ED22"

        # j (in range [1,20], padded to 32 bits)
        j = randint(1, 20)

        # LA1
        ls1_1 = genls(1, 1, self.la_id1, ls1_0)
        print(ls1_1)
        plv1_1_j = genplv(1, 1, self.la_id1, ls1_1, j)
        print(plv1_1_j)

        # LA2
        ls2_1 = genls(2, 1, self.la_id2, ls2_0)
        print(ls2_1)
        plv2_1_j = genplv(2, 1, self.la_id2, ls2_1, j)
        print(plv2_1_j)

        # lv (1,j)
        lv_1_j = genlv(1, plv1_1_j, plv2_1_j)
        print(lv_1_j)

        self.assertEqual(ls1_1, "828097e29341a95c19cf31bd0a38e028")
        self.assertEqual(plv1_1_j, 3264427119751052742155)
        self.assertEqual(ls2_1, "7d81f686b52529845e16a58d18915dc2")
        self.assertEqual(plv2_1_j, 1638125225100523861718)
        self.assertEqual(lv_1_j, 4283863095717697075421)


if __name__ == '__main__':
    unittest.main()
