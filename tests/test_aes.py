# aes_package/tests/test_aes.py
from aes_module.aes import aes_256_encrypt, aes_256_decrypt
from aes_module.byte import Byte
from aes_module.word import Word
from aes_module.state import State

def test_aes():
    key = [
        Byte(0x54), Byte(0x68), Byte(0x61), Byte(0x74),
        Byte(0x73), Byte(0x20), Byte(0x6D), Byte(0x79),
        Byte(0x20), Byte(0x4B), Byte(0x75), Byte(0x6E), 
        Byte(0x67), Byte(0x20), Byte(0x46), Byte(0x75)
    ]

    message = State([
        Word([Byte(0x54), Byte(0x77), Byte(0x6f), Byte(0x20)]),
        Word([Byte(0x4F), Byte(0x6E), Byte(0x65), Byte(0x20)]),
        Word([Byte(0x4E), Byte(0x69), Byte(0x6E), Byte(0x65)]),
        Word([Byte(0x20), Byte(0x54), Byte(0x77), Byte(0x6F)]),
    ])

    encrypted = aes_256_encrypt(message, key)
    decrypted = aes_256_decrypt(encrypted, key)
    assert str(decrypted) == str(message)