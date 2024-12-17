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

def test_maximum_byte_values(sample_key):
    """Test encryption and decryption of a message with maximum byte values."""
    max_byte_message = State([
        Word([Byte(0xFF), Byte(0xFF), Byte(0xFF), Byte(0xFF)]),
        Word([Byte(0xFF), Byte(0xFF), Byte(0xFF), Byte(0xFF)]),
        Word([Byte(0xFF), Byte(0xFF), Byte(0xFF), Byte(0xFF)]),
        Word([Byte(0xFF), Byte(0xFF), Byte(0xFF), Byte(0xFF)]),
    ])
    encrypted = aes_128_encrypt(max_byte_message, sample_key)
    decrypted = aes_128_decrypt(encrypted, sample_key)
    assert str(decrypted) == str(max_byte_message)

def test_key_edge_cases():
    """Test edge cases for the encryption key."""
    short_key = [Byte(0x01)] * 15  # One byte short
    long_key = [Byte(0x01)] * 17  # One byte too long
    valid_state = State([
        Word([Byte(0x00), Byte(0x01), Byte(0x02), Byte(0x03)]),
        Word([Byte(0x04), Byte(0x05), Byte(0x06), Byte(0x07)]),
        Word([Byte(0x08), Byte(0x09), Byte(0x0A), Byte(0x0B)]),
        Word([Byte(0x0C), Byte(0x0D), Byte(0x0E), Byte(0x0F)]),
    ])
    with pytest.raises(ValueError):
        aes_128_encrypt(valid_state, short_key)
    with pytest.raises(ValueError):
        aes_128_encrypt(valid_state, long_key)

def test_non_byte_key_values(sample_message):
    """Test behavior when the key contains non-byte values."""
    invalid_key = [0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75]  # Integers, not Byte objects
    with pytest.raises(TypeError):
        aes_128_encrypt(sample_message, invalid_key)

def test_non_word_message(sample_key):
    """Test behavior when the message contains non-word values."""
    invalid_message = [0x54, 0x68, 0x61, 0x74]  # Integers, not Word objects
    with pytest.raises(TypeError):
        aes_128_encrypt(invalid_message, sample_key)

def test_repeated_encryption_decryption(sample_key, sample_message):
    """Test multiple rounds of encryption and decryption."""
    encrypted = sample_message
    for _ in range(5):  # Perform encryption and decryption 5 times
        encrypted = aes_128_encrypt(encrypted, sample_key)
        decrypted = aes_128_decrypt(encrypted, sample_key)
        assert str(decrypted) == str(sample_message)
