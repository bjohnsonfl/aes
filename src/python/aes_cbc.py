from aes_encrypt import Cipher
from aes_decrypt import InvCipher

from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

# AES Constants
Nb = 4  # Number of words in block
block_size_bits = (Nb * 4 * 8)

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

g_plaintext  = "6bc1bee22e409f96e93d7e117393172a" \
             "ae2d8a571e03ac9c9eb76fac45af8e51" \
             "30c81c46a35ce411e5fbc1191a0a52ef" \
             "f69f2445df4f9b17ad2b417be66c3710"
g_ciphertext = "7649abac8119b246cee98e9b12e9197d" \
             "5086cb9b507219ee95db113a917678b2" \
             "73bed6b8e3c1743b7116e69e22229516" \
             "3ff1caa1681fac09120eca307586e1a7"
g_iv = "000102030405060708090a0b0c0d0e0f"

# F.2.1 CBC-AES128.Encrypt
# Key 2b7e151628aed2a6abf7158809cf4f3c
# IV 000102030405060708090a0b0c0d0e0f
# Block #1
# Plaintext 6bc1bee22e409f96e93d7e117393172a
# Input Block 6bc0bce12a459991e134741a7f9e1925
# Output Block 7649abac8119b246cee98e9b12e9197d
# Ciphertext 7649abac8119b246cee98e9b12e9197d
# Block #2
# Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
# Input Block d86421fb9f1a1eda505ee1375746972c
# Output Block 5086cb9b507219ee95db113a917678b2
# Ciphertext 5086cb9b507219ee95db113a917678b2
# Block #3
# Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
# Input Block 604ed7ddf32efdff7020d0238b7c2a5d
# Output Block 73bed6b8e3c1743b7116e69e22229516
# Ciphertext 73bed6b8e3c1743b7116e69e22229516
# Block #4
# Plaintext f69f2445df4f9b17ad2b417be66c3710
# Input Block 8521f2fd3c8eef2cdc3da7e5c44ea206
# Output Block 3ff1caa1681fac09120eca307586e1a7
# Ciphertext 3ff1caa1681fac09120eca307586e1a7
# F.2.2 CBC-AES128.Decrypt
# Key 2b7e151628aed2a6abf7158809cf4f3c
# IV 000102030405060708090a0b0c0d0e0f
# Block #1
# Ciphertext 7649abac8119b246cee98e9b12e9197d
# Input Block 7649abac8119b246cee98e9b12e9197d
# Output Block 6bc0bce12a459991e134741a7f9e1925
# Plaintext 6bc1bee22e409f96e93d7e117393172a
# Block #2
# Ciphertext 5086cb9b507219ee95db113a917678b2
# Input Block 5086cb9b507219ee95db113a917678b2
# Output Block d86421fb9f1a1eda505ee1375746972c
# Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
# Block #3
# Ciphertext 73bed6b8e3c1743b7116e69e22229516
# Input Block 73bed6b8e3c1743b7116e69e22229516
# Output Block 604ed7ddf32efdff7020d0238b7c2a5d
# Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
# Block #4
# Ciphertext 3ff1caa1681fac09120eca307586e1a7
# Input Block 3ff1caa1681fac09120eca307586e1a7
# Output Block 8521f2fd3c8eef2cdc3da7e5c44ea206
# Plaintext f69f2445df4f9b17ad2b417be66c3710

g_encrypt_blocks = [   BLOCK(1, "6bc1bee22e409f96e93d7e117393172a", "6bc0bce12a459991e134741a7f9e1925", "7649abac8119b246cee98e9b12e9197d", "7649abac8119b246cee98e9b12e9197d"),
                     BLOCK(2, "ae2d8a571e03ac9c9eb76fac45af8e51", "d86421fb9f1a1eda505ee1375746972c", "5086cb9b507219ee95db113a917678b2", "5086cb9b507219ee95db113a917678b2"),
                     BLOCK(3, "30c81c46a35ce411e5fbc1191a0a52ef", "604ed7ddf32efdff7020d0238b7c2a5d", "73bed6b8e3c1743b7116e69e22229516", "73bed6b8e3c1743b7116e69e22229516"),
                     BLOCK(4, "f69f2445df4f9b17ad2b417be66c3710", "8521f2fd3c8eef2cdc3da7e5c44ea206","3ff1caa1681fac09120eca307586e1a7", "3ff1caa1681fac09120eca307586e1a7")]

g_decrypt_blocks = [ BLOCK(1, "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d", "6bc0bce12a459991e134741a7f9e1925", "7649abac8119b246cee98e9b12e9197d"),
                   BLOCK(2, "ae2d8a571e03ac9c9eb76fac45af8e51", "5086cb9b507219ee95db113a917678b2", "d86421fb9f1a1eda505ee1375746972c", "5086cb9b507219ee95db113a917678b2"),
                   BLOCK(3, "30c81c46a35ce411e5fbc1191a0a52ef", "73bed6b8e3c1743b7116e69e22229516", "604ed7ddf32efdff7020d0238b7c2a5d", "73bed6b8e3c1743b7116e69e22229516"),
                   BLOCK(4, "f69f2445df4f9b17ad2b417be66c3710", "3ff1caa1681fac09120eca307586e1a7", "8521f2fd3c8eef2cdc3da7e5c44ea206", "3ff1caa1681fac09120eca307586e1a7")]

test_cases = [TEST_CASE(g_plaintext, g_ciphertext, g_encrypt_blocks, "2b7e151628aed2a6abf7158809cf4f3c", "ENCRYPT", g_iv),
              TEST_CASE(g_plaintext, g_ciphertext, g_decrypt_blocks, "2b7e151628aed2a6abf7158809cf4f3c", "DECRYPT", g_iv)]


def aes_cbc(input: str, key: str, iv: str, operation: str):
    if len(input) % 32:
        logger.fatal("input is not a multiple of 128 bits of data (i.e. 32 characters)")
        assert(0)

    key_len = len(key)
    if key_len != (128 / 4) and  key_len != (192 / 4) and key_len != (256 / 4):
        logger.fatal("key is not 128 bits or 192 bits of 256 bits")
        assert(0)

    if (len(iv) * 4) != (block_size_bits):
        logger.fatal(f"iv {iv} is not {block_size_bits} bits in length")
        assert(0)

    if (operation != "ENCRYPT") and (operation != "DECRYPT"):
        logger.fatal("operation: {operation} is invalid. 'ENCRYPT' or 'DECRYPT' are only valid types")
        assert(0)
    
    if isinstance(input, str):
        input_in_hex = bytes.fromhex(input)

    input_num_of_blocks = len(input) // (128 // 4)
    out = ""
    logger.debug(f"AES_ECB {operation}, {input_num_of_blocks} of blocks, key length: {key_len * 4}")
    logger.debug(f"input: {input_in_hex.hex()}")
    logger.debug(f"key: {key}\n")

    input_in_hex = bytes.fromhex(input)

    for i in range(input_num_of_blocks):
        logger.debug(f"block: {i}")
        if operation == "ENCRYPT":
            pt_in = input_in_hex[block_size_bits * i // 8: (block_size_bits * (i + 1)) // 8]
            logger.debug(f"pt_in: {pt_in}")
            if i == 0:
                chain_iv = iv
            else:
                chain_iv = last_block_ct
            last_block_ct = _aes_cbc_encrypt(pt_in, key, chain_iv)
            logger.debug(f"ct_out: {last_block_ct}")
            out += (last_block_ct)
        else:
            ct_in = input_in_hex[block_size_bits * i // 8: (block_size_bits * (i + 1)) // 8]
            logger.debug(f"ct_in: {ct_in}")
            if i == 0:
                chain_iv = iv
                last_block_ct = ct_in
            else:
                chain_iv = last_block_ct.hex()
            block_out = _aes_cbc_decrypt(ct_in, key, chain_iv)
            logger.debug(f"pt_out: {block_out}")
            out += (block_out)
            last_block_ct = ct_in
    logger.debug(f"output: {out}\n")
    return out

def _aes_cbc_encrypt(plaintext: bytes, key: str, chain_iv: str, test_block: BLOCK = None):
    chain_iv_hex = bytes.fromhex(chain_iv)

    input = bytes(a ^ b for a, b in zip(plaintext, chain_iv_hex))
    output = Cipher(input, key)
    ciphertext = output

    if test_block != None:
        assert(bytes.fromhex(test_block.input) == input)
        assert(test_block.output == output)
        assert(test_block.ciphertext == ciphertext)
    
    return ciphertext

def _aes_cbc_decrypt(ciphertext: bytes, key: str, chain_iv, test_block: BLOCK = None):
    chain_iv_hex = bytes.fromhex(chain_iv)

    input = ciphertext
    output = InvCipher(input, key)
    plaintext = bytes(a ^ b for a, b in zip(bytes.fromhex(output), chain_iv_hex))


    if test_block != None:
        assert(bytes.fromhex(test_block.input) == input)
        assert(test_block.output == output)
        assert(bytes.fromhex(test_block.plaintext) == plaintext)
    
    return (plaintext.hex())


def test_aes_cbc_encrypt_blocks():
    for test in test_cases:
        if test.operation != "ENCRYPT":
            continue
        last_block_ct = ""
        for block in test.blocks:
            if block.block_number == 1:
                chain_iv = test.iv
            else:
                chain_iv = last_block_ct
            last_block_ct = _aes_cbc_encrypt(bytes.fromhex(block.plaintext), test.key, chain_iv, block)

def test_aes_cbc_decrypt_blocks():
    for test in test_cases:
        if test.operation != "DECRYPT":
            continue
        last_block_ct = ""
        for block in test.blocks:
            if block.block_number == 1:
                chain_iv = test.iv
                last_block_ct = block.ciphertext
            else:
                chain_iv = last_block_ct
            plaintext = _aes_cbc_decrypt(bytes.fromhex(block.ciphertext), test.key, chain_iv, block)
            last_block_ct = block.ciphertext        


def test_aes_cbc_encrypt():
    for test in test_cases:
        if test.operation != "ENCRYPT":
            continue
        ct = aes_cbc(test.plaintext, test.key, test.iv, "ENCRYPT")
        assert(test.ciphertext == ct)

def test_aes_cbc_decrypt():
    for test in test_cases:
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