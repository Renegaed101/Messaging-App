from random import getrandbits

g = 2
p = 199
bits = 32


def create_public_key():
    secret = getrandbits(bits)
    public_key = pow(g, secret, p)
    return secret, public_key


def gen_shared_key(public_key, secret):
    shared_key = pow(public_key, secret, p)
    return shared_key