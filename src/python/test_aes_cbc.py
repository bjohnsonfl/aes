from dataclasses import dataclass
import logging

from aes_cbc import aes_cbc, _aes_cbc_encrypt, _aes_cbc_decrypt

logger = logging.getLogger(__name__)

@dataclass
class BLOCK:
    block_number: int
    plaintext: str
    input: str
    output: str
    ciphertext: str

@dataclass
class TEST_CASE:
    plaintext: str
    ciphertext: str
    blocks: BLOCK
    key: str
    operation: str
    iv: str = None

CBC_AES128_plaintext  = "6bc1bee22e409f96e93d7e117393172a" \
             "ae2d8a571e03ac9c9eb76fac45af8e51" \
             "30c81c46a35ce411e5fbc1191a0a52ef" \
             "f69f2445df4f9b17ad2b417be66c3710"
CBC_AES128_ciphertext = "7649abac8119b246cee98e9b12e9197d" \
             "5086cb9b507219ee95db113a917678b2" \
             "73bed6b8e3c1743b7116e69e22229516" \
             "3ff1caa1681fac09120eca307586e1a7"
CBC_AES128_iv = "000102030405060708090a0b0c0d0e0f"

CBC_AES128_encrypt_blocks = [   BLOCK(1, "6bc1bee22e409f96e93d7e117393172a", "6bc0bce12a459991e134741a7f9e1925", "7649abac8119b246cee98e9b12e9197d", "7649abac8119b246cee98e9b12e9197d"),
                                BLOCK(2, "ae2d8a571e03ac9c9eb76fac45af8e51", "d86421fb9f1a1eda505ee1375746972c", "5086cb9b507219ee95db113a917678b2", "5086cb9b507219ee95db113a917678b2"),
                                BLOCK(3, "30c81c46a35ce411e5fbc1191a0a52ef", "604ed7ddf32efdff7020d0238b7c2a5d", "73bed6b8e3c1743b7116e69e22229516", "73bed6b8e3c1743b7116e69e22229516"),
                                BLOCK(4, "f69f2445df4f9b17ad2b417be66c3710", "8521f2fd3c8eef2cdc3da7e5c44ea206","3ff1caa1681fac09120eca307586e1a7", "3ff1caa1681fac09120eca307586e1a7")]

CBC_AES128_decrypt_blocks = [   BLOCK(1, "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d", "6bc0bce12a459991e134741a7f9e1925", "7649abac8119b246cee98e9b12e9197d"),
                                BLOCK(2, "ae2d8a571e03ac9c9eb76fac45af8e51", "5086cb9b507219ee95db113a917678b2", "d86421fb9f1a1eda505ee1375746972c", "5086cb9b507219ee95db113a917678b2"),
                                BLOCK(3, "30c81c46a35ce411e5fbc1191a0a52ef", "73bed6b8e3c1743b7116e69e22229516", "604ed7ddf32efdff7020d0238b7c2a5d", "73bed6b8e3c1743b7116e69e22229516"),
                                BLOCK(4, "f69f2445df4f9b17ad2b417be66c3710", "3ff1caa1681fac09120eca307586e1a7", "8521f2fd3c8eef2cdc3da7e5c44ea206", "3ff1caa1681fac09120eca307586e1a7")]

CBC_AES128_test_cases = [TEST_CASE(CBC_AES128_plaintext, CBC_AES128_ciphertext, CBC_AES128_encrypt_blocks, "2b7e151628aed2a6abf7158809cf4f3c", "ENCRYPT", CBC_AES128_iv),
                         TEST_CASE(CBC_AES128_plaintext, CBC_AES128_ciphertext, CBC_AES128_decrypt_blocks, "2b7e151628aed2a6abf7158809cf4f3c", "DECRYPT", CBC_AES128_iv)]


def test_aes_cbc_encrypt_blocks():
    for test in CBC_AES128_test_cases:
        if test.operation != "ENCRYPT":
            continue
        last_block_ct = ""
        for block in test.blocks:
            if block.block_number == 1:
                chain_iv = test.iv
            else:
                chain_iv = last_block_ct
            res = _aes_cbc_encrypt(bytes.fromhex(block.plaintext), test.key, chain_iv)
            last_block_ct = res[0]
            assert(bytes.fromhex(block.input) == res[1])
            assert(block.output == res[2])
            assert(block.ciphertext == res[0])

def test_aes_cbc_decrypt_blocks():
    for test in CBC_AES128_test_cases:
        if test.operation != "DECRYPT":
            continue
        last_block_ct = ""
        for block in test.blocks:
            if block.block_number == 1:
                chain_iv = test.iv
                last_block_ct = block.ciphertext
            else:
                chain_iv = last_block_ct
            res = _aes_cbc_decrypt(bytes.fromhex(block.ciphertext), test.key, chain_iv)
            last_block_ct = block.ciphertext   
            assert(bytes.fromhex(block.input) == res[1])
            assert(block.output == res[2])
            assert(block.plaintext == res[0])     

def test_aes_cbc_encrypt():
    for test in CBC_AES128_test_cases:
        if test.operation != "ENCRYPT":
            continue
        ct = aes_cbc(test.plaintext, test.key, test.iv, "ENCRYPT")
        assert(test.ciphertext == ct)

def test_aes_cbc_decrypt():
    for test in CBC_AES128_test_cases:
        if test.operation != "DECRYPT":
            continue
        pt = aes_cbc(test.ciphertext, test.key, test.iv, "DECRYPT")
        assert(test.plaintext == pt)

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    test_aes_cbc_encrypt_blocks()
    test_aes_cbc_decrypt_blocks()
    test_aes_cbc_encrypt()
    test_aes_cbc_decrypt()