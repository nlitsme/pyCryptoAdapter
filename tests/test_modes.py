"""
Tests for the various ciphering mode wrappers.
"""
import unittest
from binascii import a2b_hex
import Crypto.Cipher.AES
from TestCiphers.Modes import CBC, CFB, OFB


class TestCBC(unittest.TestCase):
    """
    unittests for CBC mode wrapper.

    tests AES in ECB mode, wrapped with CBC wrapper,
    and AES with MODE_CBC against known good values
    """

    key = a2b_hex('5fac1b25b2b9b20553004e81c9f0cf8d955139e0e0acf67ee5b632beb17ffca3')
    iv = a2b_hex('0b2cf5f7cb8dc144746be0c65438bdc4')
    plain = a2b_hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
    crypted = a2b_hex('d0f5ab9d79653f8fcba5a9d3d5da75f7ce6790fd5cccf02ed5547c2a15e71e56f7b53ecec68d819758d56c79dfc45ae62364400a7128bdde1b5844df17444e16')
    cipher = Crypto.Cipher.AES

    def test_wCBC_enc(self):
        wc = CBC(self.cipher.new(self.key), IV=self.iv)
        enc_wc = wc.encrypt(self.plain)
        self.assertEqual(enc_wc, self.crypted)

    def test_wCBC_dec(self):
        wc = CBC(self.cipher.new(self.key), IV=self.iv)
        dec_wc = wc.decrypt(self.crypted)
        self.assertEqual(dec_wc, self.plain)

    def test_mCBC_enc(self):
        cc = self.cipher.new(self.key, mode=self.cipher.MODE_CBC, IV=self.iv)
        enc_cc = cc.encrypt(self.plain)
        self.assertEqual(enc_cc, self.crypted)

    def test_mCBC_dec(self):
        cc = self.cipher.new(self.key, mode=self.cipher.MODE_CBC, IV=self.iv)
        dec_cc = cc.decrypt(self.crypted)
        self.assertEqual(dec_cc, self.plain)


class TestCFB(unittest.TestCase):
    """
    unittests for CFB mode wrapper.

    tests AES in ECB mode, wrapped with CFB wrapper,
    and AES with MODE_CFB against known good values
    """
    key = a2b_hex('5fac1b25b2b9b20553004e81c9f0cf8d955139e0e0acf67ee5b632beb17ffca3')
    iv = a2b_hex('0b2cf5f7cb8dc144746be0c65438bdc4')
    plain = a2b_hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
    crypted = a2b_hex('6c78f9cec4964f312077e18a74dc03efc7c95dc3fd1045922771cea10e8b63c67c2f06a780867318bc17215cf782d04b88fdcb5b7a6536a8d4370f75fdf99838')
    cipher = Crypto.Cipher.AES

    def test_wCFB_enc(self):
        wc = CFB(self.cipher.new(self.key), IV=self.iv)
        enc_wc = wc.encrypt(self.plain)
        self.assertEqual(enc_wc, self.crypted)

    def test_wCFB_dec(self):
        wc = CFB(self.cipher.new(self.key), IV=self.iv)
        dec_wc = wc.decrypt(self.crypted)
        self.assertEqual(dec_wc, self.plain)

    def test_mCFB_enc(self):
        cc = self.cipher.new(self.key, mode=self.cipher.MODE_CFB, IV=self.iv, segment_size=128)
        enc_cc = cc.encrypt(self.plain)
        self.assertEqual(enc_cc, self.crypted)

    def test_mCFB_dec(self):
        cc = self.cipher.new(self.key, mode=self.cipher.MODE_CFB, IV=self.iv, segment_size=128)
        dec_cc = cc.decrypt(self.crypted)
        self.assertEqual(dec_cc, self.plain)


class TestOFB(unittest.TestCase):
    """
    unittests for OFB mode wrapper.

    tests AES in ECB mode, wrapped with OFB wrapper,
    and AES with MODE_OFB against known good values
    """

    key = a2b_hex('5fac1b25b2b9b20553004e81c9f0cf8d955139e0e0acf67ee5b632beb17ffca3')
    iv = a2b_hex('0b2cf5f7cb8dc144746be0c65438bdc4')
    plain = a2b_hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
    crypted = a2b_hex('6c78f9cec4964f312077e18a74dc03ef2ab016db611f52c504a7a822b9dc7f48e95effd1ce17a03c23d7315aa82b2ee4229d503cbbf3a78d13284b39228e62bc')
    cipher = Crypto.Cipher.AES

    def test_wOFB_enc(self):
        wc = OFB(self.cipher.new(self.key), IV=self.iv)
        enc_wc = wc.encrypt(self.plain)
        self.assertEqual(enc_wc, self.crypted)

    def test_wOFB_dec(self):
        wc = OFB(self.cipher.new(self.key), IV=self.iv)
        dec_wc = wc.decrypt(self.crypted)
        self.assertEqual(dec_wc, self.plain)

    def test_mOFB_enc(self):
        cc = self.cipher.new(self.key, mode=self.cipher.MODE_OFB, IV=self.iv)
        enc_cc = cc.encrypt(self.plain)
        self.assertEqual(enc_cc, self.crypted)

    def test_mOFB_dec(self):
        cc = self.cipher.new(self.key, mode=self.cipher.MODE_OFB, IV=self.iv)
        dec_cc = cc.decrypt(self.crypted)
        self.assertEqual(dec_cc, self.plain)
