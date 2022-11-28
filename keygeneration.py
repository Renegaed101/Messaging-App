from cryptography.fernet import Fernet
import os


def generateKeys(username):
    privateKey = Fernet.generate_key()
    f = open("privateKey"+username+".txt", "wb")
    f.write(privateKey)
    f.close()

    publicKey1 = Fernet.generate_key()
    f = open("publicKey1"+username+".txt", "wb")
    f.write(publicKey1)
    f.close()

    publicKey2 = Fernet.generate_key()
    f = open("publicKey2"+username+".txt", "wb")
    f.write(publicKey2)
    f.close()


def getpublicKey1(username):
    with open("publicKey1"+username+".txt") as f:
        publicKey = ''.join(f.readlines())
    return publicKey


def getpublicKey1(username):
    with open("publicKey2"+username+".txt") as f:
        publicKey2 = ''.join(f.readlines())
    return publicKey2


def getprivateKey(username):
    with open("privateKey"+username+".txt") as f:
        privateKey = ''.join(f.readlines())
    return privateKey
