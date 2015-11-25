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


if __name__ == '__main__':
    unittest.main()
