import bcrypt
import hashlib
import base64
def hash_data(data):
    """Hash the data using SHA-256 and base64 encoding."""
    if isinstance(data, str):
        data_bytes = data.encode()
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise ValueError("Data must be a string or bytes.")

    hashed_data = hashlib.sha256(data_bytes).digest()
    encoded_data = base64.b64encode(hashed_data).decode()
    print("session id in hash function", data)
    return encoded_data

print(hash_data('ashtapadhi'))
print(hash_data('ashtapadhi'))