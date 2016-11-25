"""
The Modes module has several wrapper classes, which add
a specific ciphering mode to a ECB-only class
"""
from Crypto.Util.strxor import strxor


class CBC(object):
    """
    Cipher Block Chaining (`CBC`) wrapper

    CBC is defined by the following formula:

        C[i] = Encrypt(P[i] ^ C[i-1]), C[0] = IV
        P[i] = Decrypt(C[i]) ^ C[i-1], C[0] = IV

    Usage:

        cipher = CBC(MyBlockCipher(key), IV=iv)

    The result should be the same as:

        cipher = MyBlockCipher(key, mode=MODE_CBC, IV=iv)
    """
    def __init__(self, cipher, **kwargs):
        self.cipher = cipher
        self.IV = kwargs["IV"]

    def encrypt(self, data):
        result = b''
        for o in range(0, len(data), self.cipher.block_size):
            blk = data[o:o+self.cipher.block_size]
            self.IV = self.cipher.encrypt(strxor(self.IV, blk))
            result += self.IV
        return result

    def decrypt(self, data):
        result = b''
        for o in range(0, len(data), self.cipher.block_size):
            blk = data[o:o+self.cipher.block_size]
            res = strxor(self.cipher.decrypt(blk), self.IV)
            self.IV = blk
            result += res
        return result


class CFB(object):
    """
    Cipher FeedBack (`CFB`) mode wrapper.

    CFB is defined by the following formula:

        C[i] = Encrypt(C[i-1]) ^ P[i], C[0] = IV
        P[i] = Encrypt(C[i-1]) ^ C[i], C[0] = IV

    Usage:

        cipher = CFB(MyBlockCipher(key), IV=iv)

    The result should be the same as:

        cipher = MyBlockCipher(key, mode=MODE_CFB, IV=iv, segment_size=128)
    """
    def __init__(self, cipher, **kwargs):
        self.cipher = cipher
        self.IV = kwargs["IV"]

    def encrypt(self, data):
        result = b''
        for o in range(0, len(data), self.cipher.block_size):
            blk = data[o:o+self.cipher.block_size]
            self.IV = strxor(self.cipher.encrypt(self.IV), blk)
            result += self.IV
        return result

    def decrypt(self, data):
        result = b''
        for o in range(0, len(data), self.cipher.block_size):
            blk = data[o:o+self.cipher.block_size]
            res = strxor(self.cipher.encrypt(self.IV), blk)
            self.IV = blk
            result += res
        return result


class OFB(object):
    """
    Output FeedBack (`OFB`) mode wrapper.

    CFB is defined by the following formula:

        O[-1] = IV
        O[j] = Encrypt(O[j-1])
        C[j] = P[j] ^ O[j]

    Usage:

        cipher = OFB(MyBlockCipher(key), IV=iv)

    The result should be the same as:

        cipher = MyBlockCipher(key, mode=MODE_OFB, IV=iv)
    """
    def __init__(self, cipher, **kwargs):
        self.cipher = cipher
        self.IV = kwargs["IV"]

    def encrypt(self, data):
        result = b''
        for o in range(0, len(data), self.cipher.block_size):
            self.IV = self.cipher.encrypt(self.IV)
            blk = data[o:o+self.cipher.block_size]
            result += strxor(blk, self.IV)
        return result

    def decrypt(self, data):
        return self.encrypt(data)
