# backend/utils.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os

# Simulated CA key pair (in production, securely store these)
ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_public_key = ca_private_key.public_key()

def generate_key_pair():
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def issue_certificate(username: str, public_key_pem: bytes) -> bytes:
    """Issue an X.509 certificate."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{username}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Document Signing App")
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)

def verify_certificate(cert_pem: bytes) -> bool:
    """Verify certificate signature and validity."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        now = datetime.utcnow()
        return cert.not_valid_before <= now <= cert.not_valid_after
    except Exception:
        return False

def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """Sign data with private key."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verify signature with public key."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def encrypt_file(file_path: str, recipient_public_key_pem: bytes, output_dir: str, filename: str) -> tuple:
    """Encrypt file with hybrid encryption (RSA + AES)."""
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    with open(file_path, 'rb') as f:
        data = f.read()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    public_key = serialization.load_pem_public_key(recipient_public_key_pem)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    enc_path = os.path.join(output_dir, f"{filename}.enc")
    iv_path = os.path.join(output_dir, f"{filename}.iv")
    key_path = os.path.join(output_dir, f"{filename}.key")
    with open(enc_path, 'wb') as f:
        f.write(ciphertext)
    with open(iv_path, 'wb') as f:
        f.write(iv)
    with open(key_path, 'wb') as f:
        f.write(encrypted_aes_key)
    return enc_path, iv_path, key_path

def decrypt_file(enc_path: str, iv_path: str, key_path: str, private_key_pem: bytes) -> bytes:
    """Decrypt file with hybrid encryption."""
    with open(enc_path, 'rb') as f:
        ciphertext = f.read()
    with open(iv_path, 'rb') as f:
        iv = f.read()
    with open(key_path, 'rb') as f:
        encrypted_aes_key = f.read()
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()