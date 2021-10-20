#!/usr/bin/env sage
import binascii
from pwn import xor
from Cryptodome.Util.number import long_to_bytes
from bitstring import BitArray
from sage.all import *
import requests
from curtsies.fmtfuncs import red

# ! construct the galois field
F = GF(Integer(2))['X']
(X,) = F._first_ngens(1)
G = GF(Integer(2)**Integer(128), modulus=X**Integer(128)+X **
       Integer(7)+X**Integer(2)+X+Integer(1), names=('x',))
(x,) = G._first_ngens(1)
K = G['y']
(y,) = K._first_ngens(1)


def retrieve_oracle(plaintext):
    resp = requests.get(
        'http://aes.cryptohack.org/forbidden_fruit/encrypt/' + plaintext).json()
    if 'tag' in resp:
        return resp['ciphertext'], resp['tag'], resp['nonce']
    else:
        return resp['ciphertext']


def hex_list_2_bytes_list(hex_list):
    return [binascii.unhexlify(v) for v in hex_list]


def to_gf(long_bytes):
    '''
        arithmetic operation over galois field 
        GF(2^128)
    '''
    return G([int(v) for v in BitArray(long_bytes).bin.zfill(128)])


def compute_mask(AD, c, H, L, t):
    '''
        mask computes based on this equation over GF(2^128)
        T = AAD * H^3 + C_1 * H^2 + L * H + MASK
        In AES_GCM MODE MASK = E_k(IV||0*31||1)

    '''
    return t + AD * (H**3) + c * (H**2) + L*H


def compute_tag(AD, c, H, L, mask):
    return AD * (H**3) + c * (H**2) + L * H + mask


def poly_2_hex(poly):
    '''
        e.g. 00010000
        the first bit (from left to right) is the coefficient of x^0
        the last bit is the coefficient of x^7
    '''
    return binascii.hexlify(long_to_bytes(
        int(''.join([str(v) for v in poly.polynomial().list()]), 2), 16)).decode()


def get_flag(nonce, ciphertext, tag, asso_data):
    flag = requests.get('http://aes.cryptohack.org/forbidden_fruit/decrypt/' +
                        nonce + '/' + ciphertext + '/' + tag + '/' + asso_data).json()['plaintext']
    return binascii.unhexlify(flag).decode()


# You can choose your own plaintext
plaintext_4_equation = [
    ''.join([choice('0123456789abcdef') for o in range(32)]) for v in range(2)]
tag_4_equation = [None] * 2
ciphertext_4_equation = [None] * len(plaintext_4_equation)

for i in range(len(plaintext_4_equation)):
    o1, o2, nonce = retrieve_oracle(plaintext_4_equation[i])
    ciphertext_4_equation[i] = o1
    tag_4_equation[i] = o2


ciphertext_4_equation_byte = hex_list_2_bytes_list(ciphertext_4_equation)
tag_4_equation_byte = hex_list_2_bytes_list(tag_4_equation)

# ! compute H
ciphertext_xor = xor(
    ciphertext_4_equation_byte[0], ciphertext_4_equation_byte[1])
tag_xor = xor(tag_4_equation_byte[0], tag_4_equation_byte[1])
c_xor_GF = to_gf(ciphertext_xor)
t_xor_GF = to_gf(tag_xor)
# ! t_1 + t_2 = (c1 + c2)*H^2 NOTICE: all operations are over GF(2^128)
H = (t_xor_GF / c_xor_GF).sqrt()
print(red('[+] Get H: ') + poly_2_hex(H))
# ! compute mask M = E_k(IV||0_31||1)
AAD = b'CryptoHack'
AAD_len = len(AAD)
ciphertext_len = len(ciphertext_4_equation[0]) // 2
concat_len = ((AAD_len*8) << 64) | (ciphertext_len*8)
AAD_GF = to_gf(AAD)
concat_len_GF = to_gf(long_to_bytes(concat_len))
c1 = to_gf(ciphertext_4_equation_byte[0])
c2 = to_gf(ciphertext_4_equation_byte[1])
t1 = to_gf(tag_4_equation_byte[0])
t2 = to_gf(tag_4_equation_byte[1])


mask = compute_mask(AAD_GF, c1, H, concat_len_GF, t1)
print(red('[+] MASK GET: ') + poly_2_hex(mask))
assert t2 == compute_tag(AAD_GF, c2, H, concat_len_GF, mask)

plaintext_target = b'give me the flag'
unauth_ciphertext = retrieve_oracle(
    binascii.hexlify(plaintext_target).decode())
unauth_ciphertext_GF = to_gf(binascii.unhexlify(unauth_ciphertext))
forge_tag = ''.join([str(v) for v in compute_tag(AAD_GF, unauth_ciphertext_GF, H,
                                                 concat_len_GF, mask).polynomial().list()])

forge_tag = binascii.hexlify(long_to_bytes(int(forge_tag, 2), 16)).decode()

print(red('[+] Forge Tag: ') + forge_tag)
print(red('[+] Flag: ') + get_flag(nonce, unauth_ciphertext,
      forge_tag, binascii.hexlify(AAD).decode()))
