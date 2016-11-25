from setuptools import setup
setup(
    name = "pyCryptoAdapter",
    version = "1.0",
    py_modules = ['CipherAdapter'],
    test_suite = 'tests',

    install_requires = ['PyCrypto>=2.6'],

    author = "Willem Hengeveld",
    author_email = "itsme@xs4all.nl",
    description = "PyCrypto Cipher Adapter",
    license = "MIT",
    keywords = "Crypto",
    url = "https://github.com/nlitsme/pyCryptoAdapter/",
    long_description = "Baseclass for adding new ciphers to pyCrypto",
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Python Software Foundation License',
        'License :: OSI Approved :: MIT License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],

)

