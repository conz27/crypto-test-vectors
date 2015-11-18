#!/usr/bin/env python3

import unittest

import binascii

from mac1 import *


class MAC1Tests(unittest.TestCase):
    def test_rfc_4231_vector_one(self):
        known_key1 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        known_msg1 = "4869205468657265"
        known_tag1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        result = hmac.new(binascii.unhexlify(known_key1), binascii.unhexlify(known_msg1), sha256).hexdigest()
        self.assertEqual(result, known_tag1)

    def test_rfc_4231_vector_two(self):
        known_key2 = "4a656665"
        known_msg2 = "7768617420646f2079612077616e7420666f72206e6f7468696e673f"
        known_tag2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        result = hmac.new(binascii.unhexlify(known_key2), binascii.unhexlify(known_msg2), sha256).hexdigest()
        self.assertEqual(result, known_tag2)

    def test_rfc_4231_vector_three(self):
        known_key3 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        known_msg3 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        known_tag3 = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        result = hmac.new(binascii.unhexlify(known_key3), binascii.unhexlify(known_msg3), sha256).hexdigest()
        self.assertEqual(result, known_tag3)

    def test_rfc_4231_vector_four(self):
        known_key4 = "0102030405060708090a0b0c0d0e0f10111213141516171819"
        known_msg4 = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        known_tag4 = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        result = hmac.new(binascii.unhexlify(known_key4), binascii.unhexlify(known_msg4), sha256).hexdigest()
        self.assertEqual(result, known_tag4)

    def test_rfc_4231_vector_five(self):
        known_key5 = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
        known_msg5 = "546573742057697468205472756e636174696f6e"
        known_tag5 = "a3b6167473100ee06e0c796c2955552b"
        result = hmac.new(binascii.unhexlify(known_key5), binascii.unhexlify(known_msg5), sha256).hexdigest()[:32]
        self.assertEqual(result, known_tag5)

    def test_rfc_4231_vector_six(self):
        known_key6 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        known_msg6 = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"
        known_tag6 = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        result = hmac.new(binascii.unhexlify(known_key6), binascii.unhexlify(known_msg6), sha256).hexdigest()
        self.assertEqual(result, known_tag6)

    def test_rfc_4231_vector_seven(self):
        known_key7 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        known_msg7 = "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"
        known_tag7 = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        result = hmac.new(binascii.unhexlify(known_key7), binascii.unhexlify(known_msg7), sha256).hexdigest()
        self.assertEqual(result, known_tag7)


if __name__ == '__main__':
    unittest.main()
