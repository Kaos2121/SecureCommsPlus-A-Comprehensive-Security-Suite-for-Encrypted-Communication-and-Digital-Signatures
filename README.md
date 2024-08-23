---

# SecureCommsPlus: Advanced Cryptographic Communication Framework

**SecureCommsPlus** is an advanced cryptographic framework designed to ensure secure communication between parties. The framework leverages a combination of elliptic curve cryptography (ECC), RSA, AES-GCM, HMAC, and other cryptographic primitives to provide confidentiality, integrity, and authentication in data exchange. It also includes features like hybrid encryption, certificate management, and multi-factor authentication.

## Table of Contents
1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Usage](#usage)
    - [Generating ECC Keys](#generating-ecc-keys)
    - [Storing and Loading Keys](#storing-and-loading-keys)
    - [Certificate Management](#certificate-management)
    - [Secure Message Exchange](#secure-message-exchange)
    - [Digital Signatures](#digital-signatures)
    - [Hybrid Encryption/Decryption](#hybrid-encryptiondecryption)
    - [Multi-Factor Authentication](#multi-factor-authentication)
5. [Security Considerations](#security-considerations)
6. [License](#license)

## Features
- **Elliptic Curve Cryptography (ECC):** Generate and use ECC keys for secure communication.
- **RSA Hybrid Encryption:** Securely exchange AES keys using RSA, then use AES-GCM for data encryption.
- **AES-GCM Encryption:** Ensure confidentiality and integrity of data.
- **HMAC Verification:** Verify data integrity using HMAC.
- **Certificate Management:** Generate and manage self-signed X.509 certificates.
- **Multi-Factor Authentication (MFA):** Add an extra layer of security using Time-Based One-Time Passwords (TOTP).
- **Rate-Limiting:** Prevent abuse by limiting the frequency of certain operations.
- **Detailed Logging:** Keep track of operations with comprehensive logging.

## Prerequisites
- Python 3.7 or higher
- `cryptography` library (installed via pip)
- `secrets`, `logging`, `getpass`, and other standard Python libraries

## Installation

### Step 1: Clone the Repository
Clone the repository to your local machine using:
```bash
git clone https://github.com/Kaos2121/SecureCommsPlus.git
```

### Step 2: Install Dependencies
Navigate to the project directory and install the required dependencies:
```bash
cd SecureCommsPlus
pip install -r requirements.txt
```

### Step 3: Verify Installation
Run the script to ensure everything is set up correctly:
```bash
python secure_comms_plus.py
```

## Usage

### Generating ECC Keys
ECC keys are generated using the `generate_ecc_keys()` function. This function creates a private-public key pair using the SECP521R1 curve.

```python
private_key, public_key = generate_ecc_keys()
```

### Storing and Loading Keys
Keys can be securely stored and retrieved from files using the provided functions. The keys are encrypted using a passphrase before storage.

- **Storing Keys:**
    ```python
    store_keys(private_key, public_key, 'secure_keys.pem', 'your-passphrase')
    ```

- **Loading Keys:**
    ```python
    private_key, public_key = load_keys('secure_keys.pem', 'your-passphrase')
    ```

### Certificate Management
The framework supports generating and loading self-signed X.509 certificates. These certificates can be used for authenticating parties in secure communication.

- **Generating a Certificate:**
    ```python
    certificate = generate_certificate(private_key, public_key, "Subject Name", "Issuer Name", 123456789, 365)
    ```

- **Loading a Certificate:**
    ```python
    cert = load_certificate(certificate)
    ```

### Secure Message Exchange
Messages can be securely exchanged between parties using a combination of ECC for key exchange and AES-GCM for encryption.

- **Encrypting a Message:**
    ```python
    encrypted_message = secure_message_exchange(sender_private_key, receiver_public_key, b"Confidential Message", "passphrase")
    ```

- **Decrypting a Message:**
    ```python
    decrypted_message = secure_message_reception(receiver_private_key, sender_public_key, encrypted_message, "passphrase")
    ```

### Digital Signatures
Digital signatures ensure that the message is authentic and has not been altered.

- **Signing Data:**
    ```python
    signature = sign_data(private_key, b"Message to Sign")
    ```

- **Verifying a Signature:**
    ```python
    is_valid = verify_signature(public_key, signature, b"Message to Sign")
    ```

### Hybrid Encryption/Decryption
Hybrid encryption combines RSA and AES to securely transmit data. RSA is used to encrypt the AES key, which is then used to encrypt the actual message.

- **Hybrid Encryption:**
    ```python
    hybrid_encrypted_message = hybrid_encryption(receiver_public_key, b"Message to Encrypt")
    ```

- **Hybrid Decryption:**
    ```python
    hybrid_decrypted_message = hybrid_decryption(receiver_private_key, hybrid_encrypted_message)
    ```

### Multi-Factor Authentication
For added security, the framework includes a multi-factor authentication mechanism using Time-Based One-Time Passwords (TOTP).

- **Generating an OTP:**
    ```python
    otp = time_based_one_time_password("your-secret")
    ```

- **Validating an OTP:**
    ```python
    multi_factor_authentication("your-secret")
    ```

## Security Considerations
- **Key Management:** Ensure that the passphrase used for key storage is strong and securely managed.
- **Certificate Handling:** Properly manage and store certificates to prevent unauthorized access.
- **Rate-Limiting:** The rate-limiting feature is important for preventing abuse, especially in authentication mechanisms.
- **Logging:** While logging is crucial for debugging, avoid logging sensitive information like passphrases or private keys.
- **Regular Updates:** Ensure that all cryptographic libraries are regularly updated to protect against vulnerabilities.

## License
This project is licensed under the MIT License.

---

Made by Matt Lett, [GitHub Profile](https://github.com/Kaos2121)
