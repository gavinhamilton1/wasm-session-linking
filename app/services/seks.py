from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64

# Generate ECDH key pair for the Python backend
backend_private_key = ec.generate_private_key(ec.SECP256R1())
backend_public_key = backend_private_key.public_key()

# Placeholder: Replace these with public keys extracted from QR Codes
browser_public_key_bytes = base64.b64decode("BROWSER_PUBLIC_KEY_BASE64")
mobile_public_key_bytes = base64.b64decode("MOBILE_PUBLIC_KEY_BASE64")

# Convert received public keys back to ECDH format
browser_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), browser_public_key_bytes)
mobile_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), mobile_public_key_bytes)

# Perform ECDH key exchange
shared_secret_browser = backend_private_key.exchange(ec.ECDH(), browser_public_key)
shared_secret_mobile = backend_private_key.exchange(ec.ECDH(), mobile_public_key)

# Combine both shared secrets
combined_secret = shared_secret_browser + shared_secret_mobile

# Derive final session key using HKDF
session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"3-Way Forward Secrecy Key Exchange"
).derive(combined_secret)

print("3-Way Forward Secret Session Key:", base64.b64encode(session_key).decode())
