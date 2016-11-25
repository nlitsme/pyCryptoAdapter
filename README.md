
PyCrypto BlockCipher Adapter
============================

This project shows how to extend [PyCrypto](https://www.dlitz.net/software/pycrypto/)
with your own ciphers.

In PyCrypto the various ciphering modes are added to a block cipher in two steps.
First the basic ciphering modes: `CBC`, `CFB`, `OFB`, `CTR`, these are added
to a cipher in a C file: `[block_template.c](https://github.com/dlitz/pycrypto/blob/master/src/block_template.c)`. This only works for the ciphers
bundled with PyCrypto.

The more complicated ciphering modes ( `CCM`, `EAX`, `SIV`, `OPENPGP`, `GCM` )
are added to a cipher by building upon the simple modes, in `[Crypto/Cipher/blockalgo.py](https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Cipher/blockalgo.py)`

So if you want to use blockalgo to add `CCM` to your own cipher, you will have to make sure it supports the simple ciphering modes first.

You can do this by deriving from the `_BlockCipher` class offered here.
It expects the user to implement only the `encrypt_block` and `decrypt_block` methods.

In order to add the more complex modes  you can pass the above cipher as the factory class
to a `BlockAlgo` derived object.

Three examples are provided:
  * `[AESCipher](TestCiphers/AESCipher.py)` : should behave exactly the same as `Crypto.Cipher.AES` - for testing.
  * `[TandemCipher](TestCiphers/TandemCipher.py)` : A Cipher as used in GSMK cryptophone, XORring AES and Twofish.
  * `[TwofishCipher](TestCiphers/TwofishCipher.py)`: wraps the [twofish](http://github.com/keybase/python-twofish) module, adding PyCrypto ciphering modes.
  * `[Modes.py](TestCiphers/Modes.py)`: For the purpose of testing the `CipherAdapter`, several wrappers which add a ciphering mode to a cipher, using only it's ECB mode.

Note that in `AESCipher` and `TandemCipher`  the `new` factory method is _in_ the top level class,
while in the `TwofishCipher` module the `new` method is a module level function.
These are implemented differently showing two different ways of implementing a cipher.


BUGS
====

 * For CFB mode currently only `segment_size=128` is supported.


Author: Willem Hengeveld <itsme@xs4all.nl>

