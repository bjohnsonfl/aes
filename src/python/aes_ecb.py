from aes_encrypt import Cipher
from aes_decrypt import InvCipher

from dataclasses import dataclass
import logging

import sys

logger = logging.getLogger(__name__)

# AES Constants
Nb = 4  # Number of words in block
block_size_bits = (Nb * 4 * 8)

@dataclass
class BLOCK:
    block: int
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

plaintext  = "6bc1bee22e409f96e93d7e117393172a" \
             "ae2d8a571e03ac9c9eb76fac45af8e51" \
             "30c81c46a35ce411e5fbc1191a0a52ef" \
             "f69f2445df4f9b17ad2b417be66c3710"
ciphertext = "3ad77bb40d7a3660a89ecaf32466ef97" \
             "f5d3d58503b9699de785895a96fdbaaf" \
             "43b1cd7f598ece23881b00e3ed030688" \
             "7b0c785e27e8ad3f8223207104725dd4"
# F.1.1 ECB-AES128.Encrypt
# Key 2b7e151628aed2a6abf7158809cf4f3c
# Block #1
# Plaintext 6bc1bee22e409f96e93d7e117393172a
# Input Block 6bc1bee22e409f96e93d7e117393172a
# Output Block 3ad77bb40d7a3660a89ecaf32466ef97
# Ciphertext 3ad77bb40d7a3660a89ecaf32466ef97
# Block #2
# Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
# Input Block ae2d8a571e03ac9c9eb76fac45af8e51
# Output Block f5d3d58503b9699de785895a96fdbaaf
# Ciphertext f5d3d58503b9699de785895a96fdbaaf
# Block #3
# Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
# Input Block 30c81c46a35ce411e5fbc1191a0a52ef
# Output Block 43b1cd7f598ece23881b00e3ed030688
# Ciphertext 43b1cd7f598ece23881b00e3ed030688
# Block #4
# Plaintext f69f2445df4f9b17ad2b417be66c3710
# Input Block f69f2445df4f9b17ad2b417be66c3710
# Output Block 7b0c785e27e8ad3f8223207104725dd4
# Ciphertext 7b0c785e27e8ad3f8223207104725dd4

# F.1.2 ECB-AES128.Decrypt
# Key 2b7e151628aed2a6abf7158809cf4f3c
# Block #1
# Ciphertext 3ad77bb40d7a3660a89ecaf32466ef97
# Input Block 3ad77bb40d7a3660a89ecaf32466ef97
# Output Block 6bc1bee22e409f96e93d7e117393172a
# Plaintext 6bc1bee22e409f96e93d7e117393172a
# Block #2
# Ciphertext f5d3d58503b9699de785895a96fdbaaf
# Input Block f5d3d58503b9699de785895a96fdbaaf
# Output Block ae2d8a571e03ac9c9eb76fac45af8e51
# Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
# Block #3
# Ciphertext 43b1cd7f598ece23881b00e3ed030688
# Input Block 43b1cd7f598ece23881b00e3ed030688
# Output Block 30c81c46a35ce411e5fbc1191a0a52ef
# Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
# Block #4
# Ciphertext 7b0c785e27e8ad3f8223207104725dd4
# Input Block 7b0c785e27e8ad3f8223207104725dd4
# Output Block f69f2445df4f9b17ad2b417be66c3710
# Plaintext f69f2445df4f9b17ad2b417be66c3710
encrypt_blocks = [   BLOCK(1, "6bc1bee22e409f96e93d7e117393172a", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97", "3ad77bb40d7a3660a89ecaf32466ef97"),
                     BLOCK(2, "ae2d8a571e03ac9c9eb76fac45af8e51", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf", "f5d3d58503b9699de785895a96fdbaaf"),
                     BLOCK(3, "30c81c46a35ce411e5fbc1191a0a52ef", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688", "43b1cd7f598ece23881b00e3ed030688"),
                     BLOCK(4, "f69f2445df4f9b17ad2b417be66c3710", "f69f2445df4f9b17ad2b417be66c3710","7b0c785e27e8ad3f8223207104725dd4", "7b0c785e27e8ad3f8223207104725dd4")]



decrypt_blocks = [  BLOCK(1, "3ad77bb40d7a3660a89ecaf32466ef97", "3ad77bb40d7a3660a89ecaf32466ef97", "6bc1bee22e409f96e93d7e117393172a", "6bc1bee22e409f96e93d7e117393172a"),
                    BLOCK(2, "f5d3d58503b9699de785895a96fdbaaf", "f5d3d58503b9699de785895a96fdbaaf", "ae2d8a571e03ac9c9eb76fac45af8e51", "ae2d8a571e03ac9c9eb76fac45af8e51"),
                    BLOCK(3, "43b1cd7f598ece23881b00e3ed030688", "43b1cd7f598ece23881b00e3ed030688", "30c81c46a35ce411e5fbc1191a0a52ef", "30c81c46a35ce411e5fbc1191a0a52ef"),
                    BLOCK(4, "7b0c785e27e8ad3f8223207104725dd4", "7b0c785e27e8ad3f8223207104725dd4", "f69f2445df4f9b17ad2b417be66c3710", "f69f2445df4f9b17ad2b417be66c3710")]

test_cases = [TEST_CASE(plaintext, ciphertext, encrypt_blocks, "2b7e151628aed2a6abf7158809cf4f3c", "ENCRYPT"),
              TEST_CASE(plaintext, ciphertext, decrypt_blocks, "2b7e151628aed2a6abf7158809cf4f3c", "DECRYPT")]


def aes_ecb(input: str, key: str, operation: str):
    if len(input) % 32:
        logger.fatal("input is not a multiple of 128 bits of data (i.e. 32 characters)")
        assert(0)

    key_len = len(key)
    if key_len != (128 / 4) and  key_len != (192 / 4) and key_len != (256 / 4):
        logger.fatal("key is not 128 bits or 192 bits of 256 bits")
        assert(0)

    if (operation != "ENCRYPT") and (operation != "DECRYPT"):
        logger.fatal("operation: {operation} is invalid. 'ENCRYPT' or 'DECRYPT' are only valid types")
        assert(0)

    input_num_of_blocks = len(input) // (128 // 4)
    out = ""
    logger.debug(f"\nAES_ECB {operation}, {input_num_of_blocks} of blocks, key length: {key_len * 4}")
    logger.debug(f"key: {key}")
    for i in range(input_num_of_blocks):
        logger.debug(f"block: {i}")
        if operation == "ENCRYPT":
            pt_in = input[block_size_bits * i // 4: (block_size_bits * (i + 1)) // 4]
            logger.debug(f"pt_in: {pt_in}")
            block_out = Cipher(pt_in, key)
            logger.debug(f"ct_out: {block_out}")
            out += (block_out)
        else:
            ct_in = input[block_size_bits * i // 4: (block_size_bits * (i + 1)) // 4]
            logger.debug(f"ct_in: {ct_in}")
            block_out = InvCipher(ct_in, key)
            logger.debug(f"pt_out: {block_out}")
            out += (block_out)

    
    return out

def test_aes_ecb_encrypt():
    for test in test_cases:
        if test.operation != "ENCRYPT":
            continue
        ct = aes_ecb(test.plaintext, test.key, "ENCRYPT")
        assert(test.ciphertext == ct)

def test_aes_ecb_decrypt():
    for test in test_cases:
        if test.operation != "DECRYPT":
            continue
        pt = aes_ecb(test.ciphertext, test.key, "DECRYPT")
        assert(test.plaintext == pt)

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger(__name__).setLevel(logging.DEBUG)
    test_aes_ecb_encrypt()
    test_aes_ecb_decrypt()