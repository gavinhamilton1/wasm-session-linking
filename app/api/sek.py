import logging
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

def generate_key():
    logger = logging.getLogger(__name__)
    # Set a log format
    private_key_A = ec.generate_private_key(ec.SECP256R1())

    # Exchange public keys
    public_key_A = private_key_A.public_key()
    public_key_B = private_key_B.public_key()

    logger.info(public_key_A.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    logger.info(public_key_B.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))


    # Derive shared secret
    shared_secret_A = private_key_A.exchange(ec.ECDH(), public_key_B)
    shared_secret_B = private_key_B.exchange(ec.ECDH(), public_key_A)

    logger.info(f"SECRET A= {shared_secret_A.hex()}")
    logger.info(f"SECRET B= {shared_secret_B.hex()}")

    # Ensure both sides compute the same secret
    assert shared_secret_A == shared_secret_B

    # Derive SEK using HKDF
    sek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Session Key",
    ).derive(shared_secret_A)

    print(sek.hex())  # This is the SEK
