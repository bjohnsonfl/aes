# Helper Script for test_rsp_parser.py
from Crypto.Cipher import AES

def example():
    KEY = "00000000000000000000000000000000"
    IV = "00000000000000000000000000000000"
    PLAINTEXT = "f34481ec3cc627bacd5dc3fb08f273e6"
    CIPHERTEXT = "0336763e966d92595a567cc9ce537f5e"

    cipher = AES.new(bytes.fromhex(KEY), AES.MODE_CBC,bytes.fromhex(IV))
    ct_bytes = cipher.encrypt(bytes.fromhex(PLAINTEXT))
    assert(CIPHERTEXT == ct_bytes.hex())

def aes_ecb(operation, key, iv, plaintext, ciphertext):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    if operation == "ENCRYPT":
        ct_bytes = cipher.encrypt(bytes.fromhex(plaintext))
        assert(ciphertext == ct_bytes.hex())
    else:
        pt_bytes = cipher.decrypt(bytes.fromhex(ciphertext))
        assert(plaintext == pt_bytes.hex())


def aes_cbc(operation, key, iv, plaintext, ciphertext):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC,bytes.fromhex(iv))
    if operation == "ENCRYPT":
        ct_bytes = cipher.encrypt(bytes.fromhex(plaintext))
        assert(ciphertext == ct_bytes.hex())
    else:
        pt_bytes = cipher.decrypt(bytes.fromhex(ciphertext))
        assert(plaintext == pt_bytes.hex())
