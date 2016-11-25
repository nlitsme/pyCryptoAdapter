from Crypto.Util.strxor import strxor


class _BlockCipher(object):
    """
    BlockCipher baseclass.

    Derive from this class to add the basic cipher modes
    to a cipher.

    The subclass needs to implement: encrypt_block and decrypt_block.

    """
    MODE_ECB = 1
    MODE_CBC = 2
    MODE_CFB = 3
    # MODE_PGP = 4  is no longer supported by PyCrypto
    MODE_OFB = 5
    MODE_CTR = 6

    @classmethod
    def new(cls, key, *args, **kwargs):
        return cls(key, *args, **kwargs)

    def __init__(self, *args, **kwargs):
        def getarg(pos, name, default):
            if 0<=pos<len(args):
                return args[pos]
            if name in kwargs:
                return kwargs[name]
            return default
        self.mode = getarg(0, 'mode', 1)
        self.IV = getarg(1, 'IV', b'\x00' * self.block_size)
        self.counter = getarg(-1, 'counter', None)

    def encrypt(self, data):
        result = b''
        iv = self.IV
        for o in range(0, len(data), self.block_size):
            blk = data[o:o+self.block_size]

            if self.mode == self.MODE_ECB:
                pass
            elif self.mode == self.MODE_CBC:
                blk = strxor(blk, iv)
            elif self.mode == self.MODE_CFB:
                blk2 = blk
                blk = iv
            elif self.mode == self.MODE_OFB:
                blk2 = blk
                blk = iv
            elif self.mode == self.MODE_CTR:
                blk2 = blk
                blk = self.counter()
            else:
                raise Exception("unsupported cipher mode %d" % self.mode)

            res = self.encrypt_block(blk)

            if self.mode == self.MODE_ECB:
                pass
            elif self.mode == self.MODE_CBC:
                iv = res
            elif self.mode == self.MODE_CFB:
                res = strxor(res, blk2)
                iv = res
            elif self.mode == self.MODE_OFB:
                iv = res
                res = strxor(res, blk2)
            elif self.mode == self.MODE_CTR:
                res = strxor(res[:len(blk2)], blk2)

            result += res
        self.IV = iv
        return result

    def decrypt(self, data):
        result = b''
        iv = self.IV
        for o in range(0, len(data), self.block_size):
            blk = data[o:o+self.block_size]

            if self.mode == self.MODE_ECB:
                pass
            elif self.mode == self.MODE_CBC:
                pass
            elif self.mode == self.MODE_CFB:
                blk2 = blk
                blk = iv
            elif self.mode == self.MODE_OFB:
                blk2 = blk
                blk = iv
            elif self.mode == self.MODE_CTR:
                blk2 = blk
                blk = self.counter()
            else:
                raise Exception("unsupported cipher mode %d" % self.mode)

            if self.mode in (self.MODE_CFB, self.MODE_CTR, self.MODE_OFB):
                res = self.encrypt_block(blk)
            else:
                res = self.decrypt_block(blk)

            if self.mode == self.MODE_ECB:
                pass
            elif self.mode == self.MODE_CBC:
                res = strxor(res, iv)
                iv = blk
            elif self.mode == self.MODE_CFB:
                iv = blk2
                res = strxor(res, blk2)
            elif self.mode == self.MODE_OFB:
                iv = res
                res = strxor(res, blk2)
            elif self.mode == self.MODE_CTR:
                res = strxor(res[:len(blk2)], blk2)
            result += res

        self.IV = iv
        return result
