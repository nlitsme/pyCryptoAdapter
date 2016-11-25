import unittest
from binascii import a2b_hex
import Crypto.Cipher.AES
from TestCiphers.AESCipher import AESCipher
from TestCiphers import TwofishCipher
from TestCiphers.Modes import CBC, CFB, OFB


class TestCCM(unittest.TestCase):
    """
    uinttests for AES, AESCipher in CCM mode
    """
    aes_test_cases = [
        dict(key=a2b_hex("bdf4fbd4b0546c0e9b073a31c8fd215af1d8d0ce54ac9ae109036e1794250988"), nonce=a2b_hex("2ae6fec2819229f31799f71c1f"), auth=a2b_hex("62c731543276ff94b4650f0b9e0462c593f46297ecbec56bb8c4b4d80178"), plain=a2b_hex("c891476018d7145e3096054979e4e39520876ed10e16f5e51b5b25987efc1f55"), crypt=a2b_hex("5c7ec3c3876ec7e0bce3409c9c06152f8710884b58de0f4195b008d939fe2bdfad6f2c85")),

        # two testvectors from rfc3610
        dict(key=a2b_hex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"), nonce=a2b_hex("00000003020100A0A1A2A3A4A5"), auth=a2b_hex("0001020304050607"), plain=a2b_hex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E"), crypt=a2b_hex("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0")),
        dict(key=a2b_hex("D7828D13B2B0BDC325A76236DF93CC6B"), nonce=a2b_hex("008D493B30AE8B3C9696766CFA"), auth=a2b_hex("6E37A6EF546D955D34AB6059"), plain=a2b_hex("ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4"), crypt=a2b_hex("F32905B88A641B04B9C9FFB58CC390900F3DA12AB16DCE9E82EFA16DA62059")),
    ]

    def testAES_encrypt(self):
        for t in self.aes_test_cases:
            cipher = Crypto.Cipher.AES.new(t["key"], Crypto.Cipher.AES.MODE_CCM, t["nonce"], mac_len=len(t["crypt"])-len(t["plain"]))
            cipher.update(t["auth"])
            result = cipher.encrypt(t["plain"])
            mac = cipher.digest()

            self.assertEqual(result+mac, t["crypt"])

    def testAES_decrypt(self):
        for t in self.aes_test_cases:
            maclen = len(t["crypt"]) - len(t["plain"])
            cipher = Crypto.Cipher.AES.new(t["key"], Crypto.Cipher.AES.MODE_CCM, t["nonce"], mac_len=len(t["crypt"])-len(t["plain"]))
            cipher.update(t["auth"])
            result = cipher.decrypt(t["crypt"][:-maclen])
            cipher.verify(t["crypt"][-maclen:])

            self.assertEqual(result, t["plain"])

    def testMyAES_encrypt(self):
        for t in self.aes_test_cases:
            cipher = AESCipher.new(t["key"], AESCipher.MODE_CCM, t["nonce"], mac_len=len(t["crypt"])-len(t["plain"]))
            cipher.update(t["auth"])
            result = cipher.encrypt(t["plain"])
            mac = cipher.digest()

            self.assertEqual(result+mac, t["crypt"])

    def testMyAES_decrypt(self):
        for t in self.aes_test_cases:
            maclen = len(t["crypt"]) - len(t["plain"])
            cipher = AESCipher.new(t["key"], AESCipher.MODE_CCM, t["nonce"], mac_len=len(t["crypt"])-len(t["plain"]))
            cipher.update(t["auth"])
            result = cipher.decrypt(t["crypt"][:-maclen])
            cipher.verify(t["crypt"][-maclen:])

            self.assertEqual(result, t["plain"])


class TestConsistency(unittest.TestCase):
    """
    test wrapper and MODE operations against each other.
    test AESCipher againse Crypto.Cipher.AES
    """
    key = a2b_hex('5fac1b25b2b9b20553004e81c9f0cf8d955139e0e0acf67ee5b632beb17ffca3')
    iv = a2b_hex('0b2cf5f7cb8dc144746be0c65438bdc4')
    plain = a2b_hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')

    def compare_ciphers(self, c1, c2, method):
        """ Compare the result of en/de-crypting `data` with both cipher `c1` and cipher `c2` """
        enc1 = getattr(c1, method)(self.plain)
        enc2 = getattr(c2, method)(self.plain)
        self.assertEqual(enc1, enc2)

    def encdec(self, c1, c2):
        """ Verify that encrypt followed by decypt results in the original `data` again """
        enc1 = c1.encrypt(self.plain)
        dec2 = c2.decrypt(enc1)
        self.assertEqual(self.plain, dec2)

    def decenc(self, c1, c2):
        """ Verify that decrypt followed by encypt results in the original `data` again """
        dec1 = c1.decrypt(self.plain)
        enc2 = c2.encrypt(dec1)
        self.assertEqual(self.plain, enc2)

    def _test_mode(self, c1, c2, wrapper):
        """ run compare, enc/dec tests with specified mode for the given cipher """
        ciphermode1 = getattr(c1, "MODE_"+wrapper.__name__)
        ciphermode2 = getattr(c2, "MODE_"+wrapper.__name__)
        self.compare_ciphers(c1.new(self.key, mode=ciphermode1, segment_size=128, IV=self.iv), wrapper(c2.new(self.key), IV=self.iv), "encrypt")
        self.compare_ciphers(c1.new(self.key, mode=ciphermode1, segment_size=128, IV=self.iv), wrapper(c2.new(self.key), IV=self.iv), "decrypt")
        self.compare_ciphers(wrapper(c1.new(self.key), IV=self.iv), wrapper(c2.new(self.key), IV=self.iv), "encrypt")
        self.compare_ciphers(wrapper(c1.new(self.key), IV=self.iv), wrapper(c2.new(self.key), IV=self.iv), "decrypt")
        self.compare_ciphers(c1.new(self.key, mode=ciphermode1, segment_size=128, IV=self.iv), c2.new(self.key, mode=ciphermode2, segment_size=128, IV=self.iv), "encrypt")
        self.compare_ciphers(c1.new(self.key, mode=ciphermode1, segment_size=128, IV=self.iv), c2.new(self.key, mode=ciphermode2, segment_size=128, IV=self.iv), "decrypt")

        self.decenc(wrapper(c1.new(self.key), IV=self.iv), wrapper(c2.new(self.key), IV=self.iv))
        self.encdec(wrapper(c1.new(self.key), IV=self.iv), wrapper(c2.new(self.key), IV=self.iv))
        self.decenc(c1.new(self.key, mode=ciphermode1, segment_size=128, IV=self.iv), c2.new(self.key, mode=ciphermode2, segment_size=128, IV=self.iv))
        self.encdec(c1.new(self.key, mode=ciphermode1, segment_size=128, IV=self.iv), c2.new(self.key, mode=ciphermode2, segment_size=128, IV=self.iv))

    def _test_cbc(self, c1, c2):
        """ run compare, enc/dec tests with CBC mode for the given ciphers """
        self._test_mode(c1, c2, CBC)

    def _test_cfb(self, c1, c2):
        """ run compare, enc/dec tests with CFB mode for the given ciphers """
        self._test_mode(c1, c2, CFB)

    def _test_ofb(self, c1, c2):
        """ run compare, enc/dec tests with OFB mode for the given ciphers """
        self._test_mode(c1, c2, OFB)

    def _test_encdec(self, c1, c2):
        """ run some consistency tests on ECB mode """
        self.compare_ciphers(c1.new(self.key), c2.new(self.key), "encrypt")
        self.compare_ciphers(c1.new(self.key), c2.new(self.key), "decrypt")
        self.decenc(c1.new(self.key), c2.new(self.key))
        self.encdec(c1.new(self.key), c2.new(self.key))

    def _test_modes(self, c1, c2):
        """ run ecb, cbc, cfb, ofb mode tests for the `cipher` """
        self._test_encdec(c1, c2)
        self._test_cbc(c1, c2)
        self._test_cfb(c1, c2)
        self._test_ofb(c1, c2)

    def testMyTwofish(self):
        """ run tests for our own AES blockcipher wrapper """
        self._test_modes(TwofishCipher, TwofishCipher)

    def testMyAES(self):
        """ run tests for our own AES blockcipher wrapper """
        self._test_modes(AESCipher, AESCipher)

    def testAES(self):
        """ run tests for the standard AES version """
        self._test_modes(Crypto.Cipher.AES, Crypto.Cipher.AES)

    def testBothAES(self):
        """ compare myAES against pycrypto AES """
        self._test_modes(AESCipher, Crypto.Cipher.AES)
        self._test_modes(Crypto.Cipher.AES, AESCipher)
