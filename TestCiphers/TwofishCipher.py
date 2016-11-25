"""
pyCrypto compatible wrapper for twofish module

Note that the factory function `new` is at the module level here.
"""
import twofish
import Crypto.Cipher.blockalgo
from CipherAdapter import _BlockCipher

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_OFB = 5
MODE_CTR = 6
MODE_CCM = 8


class _Twofish(_BlockCipher):
    block_size = 16

    def __init__(self, key, *args, **kwargs):
        self.tf = twofish.Twofish(key)
        _BlockCipher.__init__(self, *args, **kwargs)

    def encrypt_block(self, data):
        return self.tf.encrypt(data)

    def decrypt_block(self, data):
        return self.tf.decrypt(data)


class TwofishCipher(Crypto.Cipher.blockalgo.BlockAlgo):
    """
    TwofishCipher, subclass of BlockAlgo ( so we get the CCM, AEX, PGP, SIV, GCM cipher modes )

    factory class which can be used to test the _BlockCipher baseclass
    """
    def __init__(self, key, *args, **kwargs):
        Crypto.Cipher.blockalgo.BlockAlgo.__init__(self, _Twofish, key, *args, **kwargs)

    def __setattr__(self, name, value):
        if name=="IV":
            self._cipher.IV = value
        self.__dict__[name] = value


def new(key, *args, **kwargs):
    return TwofishCipher(key, *args, **kwargs)

