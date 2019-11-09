import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import binascii

def format_plaintext(is_admin, password):
    tmp = bytearray(str.encode(password))
    return bytes(bytearray((is_admin).to_bytes(1,"big")) + tmp)

def is_admin_cookie(decrypted_cookie):
    return decrypted_cookie[0] == 1

data = b"auth additional data"

class Encryption(object):
    def __init__(self, in_key=None):
        self._backend = default_backend()
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)
        if in_key is None:
            self._key = os.urandom(self._block_size_bytes)
        else:
            self._key = in_key

    def encrypt(self, msg):
        iv = os.urandom(self._block_size_bytes)
        encryptor = Cipher(algorithms.AES(self._key), modes.GCM(iv), self._backend).encryptor()
        encryptor.authenticate_additional_data(data)
        ct = encryptor.update(msg) + encryptor.finalize()
        return iv + encryptor.tag + ct
    
    def decrypt(self, ctx):
        iv, ct = ctx[:self._block_size_bytes], ctx[self._block_size_bytes:]
        tag, ct = ct[:self._block_size_bytes], ct[self._block_size_bytes:]

        decryptor = Cipher(algorithms.AES(self._key), modes.GCM(iv, tag), self._backend).decryptor()
        decryptor.authenticate_additional_data(data)
        return decryptor.update(ct) + decryptor.finalize()

        
if __name__=='__main__':
    pass