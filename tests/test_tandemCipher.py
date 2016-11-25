import unittest
from binascii import a2b_hex
from TestCiphers.TandemCipher import TandemCipher
import Crypto.Util


class TestTandem(unittest.TestCase):
    """
    unittests for TandemCipher in ECB, CTR mode
    """
    def test1(self):
        data = a2b_hex("00" * 16)
        match = a2b_hex("275380c1d651143b023a6c1090979f74")
        key = a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")

        cipher = TandemCipher.new(key, mode=TandemCipher.MODE_ECB)
        self.assertEqual(cipher.encrypt(data), match)

    def test2(self):
        data = a2b_hex("22"+("00" * 15))
        match = a2b_hex("86a3f81a0638d15794bc704a8ef1953d")
        key = a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")

        cipher = TandemCipher.new(key, mode=TandemCipher.MODE_ECB)
        self.assertEqual(cipher.encrypt(data), match)

    def test_CTR(self):
        data = a2b_hex("00000000000000000000000000000000")
        match = a2b_hex("275380c1d651143b023a6c1090979f74")
        match2 = a2b_hex("86a3f81a0638d15794bc704a8ef1953d")
        key = a2b_hex("0000000000000000000000000000000000000000000000000000000000000000")

        cipher = TandemCipher.new(key, mode=TandemCipher.MODE_CTR, counter=Crypto.Util.Counter.new(128, little_endian=True, initial_value=0))
        self.assertEqual(cipher.encrypt(data), match)
        for _ in range(33):
            cipher.encrypt(data)
        self.assertEqual(cipher.encrypt(data), match2)


class TestTandemCCM(unittest.TestCase):
    def testTandem_enc1(self):
        nonce = a2b_hex("a8912f9c7a879a96cb4a5625")
        crypt = a2b_hex("2cec1ffad90827cdf49ec71ddf447b5bb51dad215ad6c1a08aa5b61e57972c0d2c468ea83404e01c5a93510ceb212538")
        key = a2b_hex("87ee493a57f0d1ec37bbc29b6505c3bdcf81234b2ec4d9b60ba33ea5be23afdb")
        plain = a2b_hex("5fac1b25b2b9b20553004e81c9f0cf8d955139e0e0acf67ee5b632beb17ffca3")

        mac = crypt[len(plain):]
        crypt = crypt[:len(plain)]
        auth = b''

        cipher = TandemCipher.new(key, TandemCipher.MODE_CCM, nonce, mac_len=16)
        cipher.update(auth)
        result = cipher.encrypt(plain)
        macresult = cipher.digest()

        self.assertEqual(result, crypt)
        self.assertEqual(macresult, mac)

    def testTandem_dec1(self):
        nonce = a2b_hex("a8912f9c7a879a96cb4a5625")
        crypt = a2b_hex("2cec1ffad90827cdf49ec71ddf447b5bb51dad215ad6c1a08aa5b61e57972c0d2c468ea83404e01c5a93510ceb212538")
        key = a2b_hex("87ee493a57f0d1ec37bbc29b6505c3bdcf81234b2ec4d9b60ba33ea5be23afdb")
        plain = a2b_hex("5fac1b25b2b9b20553004e81c9f0cf8d955139e0e0acf67ee5b632beb17ffca3")

        mac = crypt[len(plain):]
        crypt = crypt[:len(plain)]
        auth = b''

        cipher = TandemCipher.new(key, TandemCipher.MODE_CCM, nonce, mac_len=16)
        cipher.update(auth)
        result = cipher.decrypt(crypt)

        cipher.verify(mac)

        self.assertEqual(result, plain)
