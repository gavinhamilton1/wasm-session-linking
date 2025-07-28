import base64
from cryptography.hazmat.primitives.serialization import load_der_public_key

pub_key_b64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJkjqmr46AoQTyArY6aISpLFlUYU68UotrMXRsXdoBEEnPGGTdfFaBmuQ9pk4P/7B5dUc+ocqA4upVFiNHMhC3A=="
pub_key_bytes = base64.b64decode(pub_key_b64)
public_key = load_der_public_key(pub_key_bytes)
print(public_key)
