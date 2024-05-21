
import os
import base64

def generate_secret_key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')

if __name__ == '__main__':
    print(generate_secret_key())
