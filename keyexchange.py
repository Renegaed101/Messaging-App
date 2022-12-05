
from random import getrandbits
from Crypto.Cipher import AES

g = 10781
p = 100153
bits = 128


def create_public_key():
    secret = getrandbits(bits)
    public_key = pow(g, secret, p)
    return secret, public_key


def gen_shared_key(public_key, secret):
    shared_key = pow(public_key, secret, p)
    converted_to_16_bytes = []  # Will be an array of bytes
    for i in range(16):
        # Get the i'th byte counting from the least significant end
        b = shared_key >> (i * 8) & 0xFF
        converted_to_16_bytes.append(b)
    return bytearray(converted_to_16_bytes) 

# encrypts message before being sent
def encryptMessage(message, sharedKey):

    cipher = AES.new(sharedKey, AES.MODE_EAX)
    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(message.encode('ascii'))

    return ciphertext, tag, nonce


# Decrypts recieved message

def decryptMessage(ciphertext, tag, nonce, sharedKey):
    cipher = AES.new(sharedKey, AES.MODE_EAX, nonce=nonce)

    message = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return message.decode('ascii')
    except:
        return False