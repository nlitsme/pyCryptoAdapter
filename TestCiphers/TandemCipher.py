"""
`TandemCipher` is the cipher as used in many GSMK products.

It XORs the result of an AES and a Twofish encryption,
each initialized with a different SHA256 of the masterkey.

Note that I am using a factory class here, instead of a factory module as is common in pyCrypto.
"""
from Crypto.Util.strxor import strxor
import Crypto.Cipher.AES
import Crypto.Hash.SHA256
from CipherAdapter import _BlockCipher
from TestCiphers import TwofishCipher


def sha256(data):
    return Crypto.Hash.SHA256.new(data).digest()


class _Tandem(_BlockCipher):
    """
    _Tandem, subclass of _BlockCipher.

    implements the actual Tandem cipher in ECB mode
    """
    block_size = Crypto.Cipher.AES.block_size

    def __init__(self, key, *args, **kwargs):
        self.c1 = Crypto.Cipher.AES.new(sha256(key+b'\x00'))
        self.c2 = TwofishCipher.new(sha256(key+b'\x01'))
        assert self.c1.block_size == self.c2.block_size

        _BlockCipher.__init__(self, *args, **kwargs)

    def encrypt_block(self, data):
        return strxor(self.c1.encrypt(data), self.c2.encrypt(data))

    def decrypt_block(self, data):
        return strxor(self.c1.decrypt(data), self.c2.decrypt(data))


class TandemCipher(Crypto.Cipher.blockalgo.BlockAlgo):
    """
    TandemCipher, subclass of BlockAlgo ( so we get the CCM, AEX, PGP, SIV, GCM cipher modes )
    """
    MODE_ECB = 1
    MODE_CBC = 2
    MODE_CFB = 3
    MODE_OFB = 5
    MODE_CTR = 6
    MODE_CCM = 8

    @classmethod
    def new(cls, key, *args, **kwargs):
        return cls(key, *args, **kwargs)

    def __init__(self, key, *args, **kwargs):
        Crypto.Cipher.blockalgo.BlockAlgo.__init__(self, _Tandem, key, *args, **kwargs)

    def __setattr__(self, name, value):
        if name=="IV":
            self._cipher.IV = value
        self.__dict__[name] = value
