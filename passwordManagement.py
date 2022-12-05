import hashlib
import hmac
from cryptography.fernet import Fernet
import base64
import mongoconfig

salt = "aosdfhiuwqehj"


def encrypt(password):
    return hash_new_password(password, salt.encode())


def check_password(password, encryptedpassword):
    return is_correct_password(salt.encode(), encryptedpassword, password)


def hash_new_password(password, salt):
    # Hash password using salt
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return pw_hash


def is_correct_password(salt: bytes, pw_hash: bytes, password: str) -> bool:
    # Check whether password matches using hashed password and salt used
    return hmac.compare_digest(
        pw_hash,
        hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    )


def encrypt_using_password(message, password):
    key = base64.urlsafe_b64encode(password)
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    return encrypted


def decrypt_using_password(encrypted_message, password):
    key = base64.urlsafe_b64encode(password)
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message.decode())
    return decrypted_message
