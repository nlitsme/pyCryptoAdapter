"""
AESCipher, based on the `_BlockCipher` adapter class.

The purpose of `AESCipher` is that I can verify the proper working
of `_BlockCipher` against the `Crypto.Cipher.AES` class.

Note that I am using a factory class here, instead of a factory module as is common in pyCrypto.
"""
from CipherAdapter import _BlockCipher
import Crypto.Cipher.AES


class _AES(_BlockCipher):
    """
    _AES, subclass of _BlockCipher.

    implements the actual AES cipher in ECB mode.

    Use case: verifying the _BlockCipher baseclass implementation against
    the 'real' AES class.
    """
    block_size = Crypto.Cipher.AES.block_size

    def __init__(self, key, *args, **kwargs):
        self.c1 = Crypto.Cipher.AES.new(key)
        _BlockCipher.__init__(self, *args, **kwargs)

    def encrypt_block(self, data):
        return self.c1.encrypt(data)

    def decrypt_block(self, data):
        return self.c1.decrypt(data)


class AESCipher(Crypto.Cipher.blockalgo.BlockAlgo):
    """
    AESCipher, subclass of BlockAlgo ( so we get the CCM, AEX, PGP, SIV, GCM cipher modes )

    factory class which can be used to test the _BlockCipher baseclass
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
        Crypto.Cipher.blockalgo.BlockAlgo.__init__(self, _AES, key, *args, **kwargs)

    def __setattr__(self, name, value):
        if name=="IV":
            self._cipher.IV = value
        self.__dict__[name] = value
