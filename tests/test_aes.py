# aes_package/tests/test_aes.py

import pytest
from aes_module.aes import aes_128_encrypt, aes_128_decrypt
from aes_module.byte import Byte
from aes_module.word import Word
from aes_module.state import State

@pytest.fixture
def sample_key():
    return [
        Byte(0x54), Byte(0x68), Byte(0x61), Byte(0x74),
        Byte(0x73), Byte(0x20), Byte(0x6D), Byte(0x79),
        Byte(0x20), Byte(0x4B), Byte(0x75), Byte(0x6E), 
        Byte(0x67), Byte(0x20), Byte(0x46), Byte(0x75)
    ]

@pytest.fixture
def sample_message():
    return State([
        Word([Byte(0x54), Byte(0x77), Byte(0x6f), Byte(0x20)]),
        Word([Byte(0x4F), Byte(0x6E), Byte(0x65), Byte(0x20)]),
        Word([Byte(0x4E), Byte(0x69), Byte(0x6E), Byte(0x65)]),
        Word([Byte(0x20), Byte(0x54), Byte(0x77), Byte(0x6F)]),
    ])

def test_aes_encrypt_decrypt(sample_key, sample_message):
    """Test AES encryption and decryption."""
    encrypted = aes_128_encrypt(sample_message, sample_key)
    decrypted = aes_128_decrypt(encrypted, sample_key)
    print(sample_message)
    print(encrypted)
    assert str(decrypted) == str(sample_message)

def test_aes_idempotence(sample_key, sample_message):
    """Test that encrypting and decrypting multiple times yields the original message."""
    encrypted = aes_128_encrypt(sample_message, sample_key)
    decrypted = aes_128_decrypt(encrypted, sample_key)
    re_encrypted = aes_128_encrypt(decrypted, sample_key)
    assert str(encrypted) == str(re_encrypted)

def test_invalid_key(sample_message):
    """Test behavior when an invalid key is provided."""
    invalid_key = [Byte(0x00) for _ in range(10)]  # Incorrect key length
    with pytest.raises(ValueError):
        aes_128_encrypt(sample_message, invalid_key)

def test_invalid_message_structure(sample_key):
    """Test behavior with an invalid message structure."""
    invalid_message = [Word([Byte(0x00), Byte(0x00), Byte(0x00), Byte(0x00)])]  # Not a valid State
    with pytest.raises(TypeError):
        aes_128_encrypt(invalid_message, sample_key)
