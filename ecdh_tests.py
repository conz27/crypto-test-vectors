#!/usr/bin/env python3

import unittest
import binascii

from ecdh import *


class ECDHTests(unittest.TestCase):
    def setUp(self):
        pass

    def test_nist_vector_zero(self):
        # Test vector #0
        QCAVSx = 0x700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287
        QCAVSy = 0xdb71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac
        dIUT = 0x7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534
        QIUTx = 0xead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230
        QIUTy = 0x28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141
        ZIUT = 0x46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_one(self):
        QCAVSx = 0x809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae
        QCAVSy = 0xb29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3
        dIUT = 0x38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5
        QIUTx = 0x119f2f047902782ab0c9e27a54aff5eb9b964829ca99c06b02ddba95b0a3f6d0
        QIUTy = 0x8f52b726664cac366fc98ac7a012b2682cbd962e5acb544671d41b9445704d1d
        ZIUT = 0x057d636096cb80b67a8c038c890e887d1adfa4195e9b3ce241c8a778c59cda67
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_two(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_three(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_four(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_five(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_six(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_seven(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_eight(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_nine(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_ten(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_eleven(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_twelve(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_thirteen(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_fourteen(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_fifteen(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_sixteen(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_seventeen(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_eighteen(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_nineteen(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_twenty(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_twenty_one(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_twenty_two(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_twenty_three(self):
        self.assertTrue(False)  # fail test when no test

    def test_nist_vector_twenty_four(self):
        self.assertTrue(False)  # fail test when no test


if __name__ == '__main__':
    unittest.main()

