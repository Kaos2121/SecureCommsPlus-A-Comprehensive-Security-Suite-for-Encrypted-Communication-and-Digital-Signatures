import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256, SHA512, SHA1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from os import urandom, path
from base64 import b64encode, b64decode
from hmac import compare_digest
from getpass import getpass
import time
import secrets
import hmac
import hashlib

backend = default_backend()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Key and Certificate Management

def generate_ecc_keys():
    logger.info("Generating ECC keys...")
    private_key = ec.generate_private_key(ec.SECP521R1(), backend)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data, backend)

def serialize_private_key(private_key, passphrase):
    encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm
    )

def deserialize_private_key(pem_data, passphrase):
    return serialization.load_pem_private_key(pem_data, passphrase.encode(), backend)

def generate_certificate(private_key, public_key, subject_name, issuer_name, serial_number, days_valid):
    logger.info("Generating self-signed certificate...")
    from cryptography.x509.oid import NameOID
    from cryptography import x509
    from datetime import datetime, timedelta

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_name),
    ])

    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        public_key).serial_number(serial_number).not_valid_before(
        datetime.utcnow()).not_valid_after(
        datetime.utcnow() + timedelta(days=days_valid)).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(subject_name)]), critical=False
    ).sign(private_key, hashes.SHA256(), backend)
    
    return cert.public_bytes(serialization.Encoding.PEM)

def load_certificate(cert_pem):
    from cryptography import x509
    return x509.load_pem_x509_certificate(cert_pem, backend)

# Secure Communication

def generate_shared_secret(private_key, peer_public_key):
    logger.info("Generating shared secret...")
    return private_key.exchange(ECDH(), peer_public_key)

def derive_key(shared_secret, info, salt=None, length=32):
    hkdf = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=info.encode(),
        backend=backend
    )
    return hkdf.derive(shared_secret)

def pad_data(data):
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad_data(padded_data):
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def encrypt_data(key, plaintext):
    iv = urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=backend
    ).encryptor()

    padded_data = pad_data(plaintext)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return b64encode(iv + encryptor.tag + ciphertext).decode()

def decrypt_data(key, encrypted_data):
    encrypted_data = b64decode(encrypted_data)
    iv, tag, ciphertext = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=backend
    ).decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_data(padded_data)

def hash_data(data):
    digest = hashes.Hash(hashes.SHA512(), backend=backend)
    digest.update(data)
    return digest.finalize()

def hmac_key_derivation(passphrase, salt, length=32):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        iterations=300000,
        backend=backend
    )
    return kdf.derive(passphrase.encode())

def hmac_verification(key, data):
    h = HMAC(key, SHA512(), backend=backend)
    h.update(data)
    return h.finalize()

# Enhanced Features

def secure_message_exchange(sender_private_key, receiver_public_key, message, passphrase, metadata=None):
    logger.info("Exchanging secure message...")
    salt = urandom(16)
    shared_secret = generate_shared_secret(sender_private_key, receiver_public_key)
    derived_key = derive_key(shared_secret, "message exchange")
    key = hmac_key_derivation(passphrase, salt)

    encrypted_message = encrypt_data(derived_key, message)
    signature = hmac_verification(key, encrypted_message.encode())
    
    if metadata:
        metadata_encrypted = encrypt_data(derived_key, metadata.encode())
        return b64encode(salt + encrypted_message.encode() + metadata_encrypted.encode() + signature).decode()
    else:
        return b64encode(salt + encrypted_message.encode() + signature).decode()

def secure_message_reception(receiver_private_key, sender_public_key, encrypted_data, passphrase):
    logger.info("Receiving and decrypting message...")
    decoded_data = b64decode(encrypted_data)
    salt = decoded_data[:16]
    encrypted_message = decoded_data[16:-64].decode()
    signature = decoded_data[-64:]

    shared_secret = generate_shared_secret(receiver_private_key, sender_public_key)
    derived_key = derive_key(shared_secret, "message exchange")
    key = hmac_key_derivation(passphrase, salt)
    
    if not compare_digest(hmac_verification(key, encrypted_message.encode()), signature):
        logger.error("Message integrity compromised.")
        raise ValueError("Message integrity compromised.")

    return decrypt_data(derived_key, encrypted_message)

def sign_data(private_key, data):
    return private_key.sign(
        data,
        ec.ECDSA(hashes.SHA512())
    )

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA512()))
        return True
    except ec.InvalidSignature as e:
        logger.error(f"Signature verification failed: {e}")
        return False

def multi_factor_authentication(secret):
    otp = time_based_one_time_password(secret)
    print("Please enter the OTP sent to your registered device:")
    user_otp = getpass("OTP: ")
    if user_otp != str(otp):
        logger.error("Invalid OTP provided.")
        raise ValueError("Invalid OTP")

def time_based_one_time_password(secret, interval=30):
    counter = int(time.time() / interval)
    hmac_result = hmac.new(secret.encode(), counter.to_bytes(8, 'big'), hashlib.sha1).digest()
    otp = int.from_bytes(hmac_result[:4], 'big') & 0x7FFFFFFF
    return otp % 1000000

def rate_limit(func):
    last_called = {}

    def wrapper(*args, **kwargs):
        user_id = args[0] if args else 'default'
        now = time.time()

        if user_id in last_called and now - last_called[user_id] < 60:
            logger.warning("Rate limit exceeded.")
            raise ValueError("Rate limit exceeded. Please wait before retrying.")

        last_called[user_id] = now
        return func(*args, **kwargs)

    return wrapper

@rate_limit
def store_keys(private_key, public_key, filename, passphrase):
    with open(filename, 'wb') as f:
        f.write(serialize_private_key(private_key, passphrase))
        f.write(serialize_public_key(public_key))

@rate_limit
def load_keys(filename, passphrase):
    with open(filename, 'rb') as f:
        private_key = deserialize_private_key(f.read(), passphrase)
        public_key = deserialize_public_key(f.read())
    return private_key, public_key

def generate_key_file(filename, passphrase):
    private_key, public_key = generate_ecc_keys()
    store_keys(private_key, public_key, filename, passphrase)
    logger.info(f"Keys generated and stored in {filename}")

def load_or_generate_keys(filename, passphrase):
    if path.exists(filename):
        logger.info(f"Loading keys from {filename}")
        return load_keys(filename, passphrase)
    else:
        logger.info(f"No existing keys found. Generating new keys...")
        return generate_key_file(filename, passphrase)

# Advanced Encryption and Decryption

def rsa_encrypt(public_key, plaintext):
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def hybrid_encryption(receiver_public_key, plaintext):
    logger.info("Performing hybrid encryption...")
    aes_key = urandom(32)
    encrypted_aes_key = rsa_encrypt(receiver_public_key, aes_key)
    encrypted_message = encrypt_data(aes_key, plaintext)
    return b64encode(encrypted_aes_key + b'::' + encrypted_message.encode()).decode()

def hybrid_decryption(receiver_private_key, encrypted_data):
    logger.info("Performing hybrid decryption...")
    encrypted_data = b64decode(encrypted_data)
    encrypted_aes_key, encrypted_message = encrypted_data.split(b'::')
    aes_key = rsa_decrypt(receiver_private_key, encrypted_aes_key)
    return decrypt_data(aes_key, encrypted_message.decode())

def main():
    secret = secrets.token_hex(16)
    multi_factor_authentication(secret)

    key_filename = "secure_keys.pem"
    passphrase = getpass("Enter a passphrase for key storage: ")
    
    sender_private_key, sender_public_key = load_or_generate_keys(key_filename, passphrase)
    receiver_private_key, receiver_public_key = load_or_generate_keys(key_filename, passphrase)
    
    message = b"Confidential communication secured with ECC and AES-GCM."
    encrypted_message = secure_message_exchange(sender_private_key, receiver_public_key, message, passphrase)
    decrypted_message = secure_message_reception(receiver_private_key, sender_public_key, encrypted_message, passphrase)
    
    assert message == decrypted_message, "Decryption failed; integrity compromised."

    print(f"Original Message: {message.decode()}")
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Decrypted Message: {decrypted_message.decode()}")

    signature = sign_data(sender_private_key, message)
    is_valid = verify_signature(sender_public_key, signature, message)
    logger.info(f"Signature valid: {is_valid}")

    hybrid_encrypted_message = hybrid_encryption(receiver_public_key, message)
    hybrid_decrypted_message = hybrid_decryption(receiver_private_key, hybrid_encrypted_message)

    assert message == hybrid_decrypted_message, "Hybrid Decryption failed; integrity compromised."
    print(f"Hybrid Encrypted Message: {hybrid_encrypted_message}")
    print(f"Hybrid Decrypted Message: {hybrid_decrypted_message.decode()}")

    certificate = generate_certificate(sender_private_key, sender_public_key, "Sender", "Sender", 123456789, 365)
    loaded_cert = load_certificate(certificate)
    print(f"Generated Certificate:\n{certificate.decode()}")

if __name__ == "__main__":
    main()



# Made by Matt Lett, (github.com/Kaos2121)
