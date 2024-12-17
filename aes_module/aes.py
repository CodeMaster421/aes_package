from cipher import CIPHER, INVCIPHER, KEYEXPANSION
from byte import Byte
from word import Word
from state import State

def aes_128_encrypt(message, key):
    return CIPHER(message, 10, KEYEXPANSION(key, 4, 10))

def aes_128_decrypt(message, key):
    return INVCIPHER(message, 10, KEYEXPANSION(key, 4, 10))

def aes_192_encrypt(message, key):
    return CIPHER(message, 10, KEYEXPANSION(key, 6, 12))

def aes_192_decrypt(message, key):
    return INVCIPHER(message, 10, KEYEXPANSION(key, 6, 12))

def aes_256_encrypt(message, key):
    return CIPHER(message, 10, KEYEXPANSION(key, 8, 14))

def aes_256_decrypt(message, key):
    return INVCIPHER(message, 10, KEYEXPANSION(key, 8, 14))
