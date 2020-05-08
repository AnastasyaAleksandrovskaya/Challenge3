# Imports
import math
import base64
import decimal
from p39 import RSA
# Given
given_string = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="

def check_parity(ciphertext, rsa):
    return rsa.decryptnum(ciphertext)&amp; 1

rsa = RSA(1024)
ciphertext = rsa.encrypt(b"Hello")
print(check_parity(ciphertext, rsa))
# 1

def parity_attack(message, rsa):
    (_, n) = rsa.pub
    ciphertext = rsa.encryptnum(int.from_bytes(message, "big"))

    multiplier = rsa.encryptnum(2)

    lower_bound = decimal.Decimal(0)
    upper_bound = decimal.Decimal(n)

    num_iter = int(math.ceil(math.log(n, 2)))
    decimal.getcontext().prec = num_iter

    for _ in range(num_iter):
        ciphertext = (ciphertext * multiplier) % n
        if check_parity(ciphertext, rsa)&amp; 1:
            lower_bound = (lower_bound + upper_bound) / 2
        else:
            upper_bound = (lower_bound + upper_bound) / 2

    return int(upper_bound).to_bytes((int(upper_bound).bit_length() + 7) // 8, "big").decode("utf-8")

byte_string = base64.b64decode(given_string)
plaintext = parity_attack(byte_string, RSA(1024))