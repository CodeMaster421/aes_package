# AES Encryption Package

A Python package for AES (Advanced Encryption Standard) encryption and decryption, supporting AES-128, AES-192, and AES-256 bit encryption. This package is designed with a modular structure to make it easy to integrate into your projects and extend for custom requirements.

---

## **Features**
- **Encryption and Decryption**: Securely encrypt and decrypt data using AES with three different key lengths:
  - **AES-128**: 128-bit key size
  - **AES-192**: 192-bit key size
  - **AES-256**: 256-bit key size
- **Key Expansion**: Implements AES key schedule for efficient key derivation.
- **Modular Design**: Core components like `State`, `Word`, and `Byte` are reusable, simplifying extension or adaptation.
- **High Performance**: Optimized implementation for fast encryption and decryption.
- **Cross-Platform**: Works seamlessly across Windows, macOS, and Linux systems.

---

## **Installation**

Install the package using `pip`:

```bash
pip install aes_package
```

---

## **Usage**

This package provides functions to perform encryption and decryption easily. Below are some usage examples:

### **Encrypting a Message**
```python
from aes_module import aes_128_encrypt

# Define your message and key
message = "This is a secret message"
key = "mysecurekey12345"  # Must match the required key length

# Encrypt the message
encrypted_message = aes_128_encrypt(message, key)
print("Encrypted:", encrypted_message)
```

### **Decrypting a Message**
```python
from aes_module import aes_128_decrypt

# Decrypt the message
decrypted_message = aes_128_decrypt(encrypted_message, key)
print("Decrypted:", decrypted_message)
```

---

## **Available Functions**

The following functions are provided in the package:

### Encryption
- `aes_128_encrypt(message, key)`: Encrypt a message using AES-128.
- `aes_192_encrypt(message, key)`: Encrypt a message using AES-192.
- `aes_256_encrypt(message, key)`: Encrypt a message using AES-256.

### Decryption
- `aes_128_decrypt(message, key)`: Decrypt a message encrypted with AES-128.
- `aes_192_decrypt(message, key)`: Decrypt a message encrypted with AES-192.
- `aes_256_decrypt(message, key)`: Decrypt a message encrypted with AES-256.

---

## **Testing**

This package includes test cases to ensure reliability. You can run the tests using `pytest`:

1. Install `pytest` if not already installed:
   ```bash
   pip install pytest
   ```

2. Run the tests:
   ```bash
   pytest tests/
   ```

---

## **Requirements**

- **Python Version**: The package requires Python 3.6 or later.
- **Dependencies**: No external dependencies are required beyond the Python standard library.

---

## **How AES Works**

AES is a symmetric block cipher widely used in modern encryption. It works by processing data in fixed-size blocks (128 bits) and applying multiple rounds of substitutions, permutations, and mathematical transformations.

### **Key Lengths**
- **AES-128**: Uses a 128-bit key (10 rounds of encryption).
- **AES-192**: Uses a 192-bit key (12 rounds of encryption).
- **AES-256**: Uses a 256-bit key (14 rounds of encryption).

---

## **Contributing**

We welcome contributions to improve the package! To contribute:

1. Fork the repository on GitHub.
2. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes with descriptive messages.
4. Push the branch and submit a Pull Request.

---

## **License**

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---

## **Acknowledgments**

Special thanks to all contributors and the cryptography community for their continued development of secure encryption standards.
