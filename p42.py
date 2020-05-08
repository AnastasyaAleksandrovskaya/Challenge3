# Imports
import re
import hashlib
from p39 import RSA

# Given
message = "hi mom"
ASN1_SHA1 = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"

class RSA_Digital_Signature(RSA):
    """
    Extends the RSA class coded before with the sign / verify functions.
    """

    def generate_signature(self, message):
        digest = hashlib.sha1(message).digest()
        block = b'\x00\x01' + (b'\xff' * (128 - len(digest) - 3 - 15)) + b'\x00' + ASN1_SHA1 + digest
        signature = self.decrypt(int.from_bytes(block, "big"), "big")
        return signature

    def verify_signature(self, message, signature):
        cipher = self.encrypt(signature, "big")
        block = b'\x00' + cipher.to_bytes((cipher.bit_length() + 7) // 8, "big")
        r = re.compile(b'\x00\x01\xff+?\x00.{15}(.{20})', re.DOTALL)
        m = r.match(block)
        if not m:
            return False
        digest = m.group(1)
        return digest == hashlib.sha1(message).digest()

rsa = RSA_Digital_Signature(1024)
signature = rsa.generate_signature(message.encode())
if not rsa.verify_signature(message.encode(), signature):
    raise Exception(message + b" has invalid signature " + signature)
else:
    print("> Signature verified for message:", message)
