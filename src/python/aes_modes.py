from python.aes_encrypt import Cipher
from python.aes_decrypt import InvCipher

import logging

logger = logging.getLogger(__name__)

# AES Constants
Nb = 4  # Number of words in block
block_size_bits = (Nb * 4 * 8)


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
    
    if isinstance(input, str):
        input_in_hex = bytes.fromhex(input)

    input_num_of_blocks = len(input) // (128 // 4)
    out = ""
    logger.debug(f"AES_ECB {operation}, {input_num_of_blocks} of blocks, key length: {key_len * 4}")
    logger.debug(f"input: {input_in_hex.hex()}")
    logger.debug(f"key: {key}\n")


    for i in range(input_num_of_blocks):
        logger.debug(f"block: {i}")
        if operation == "ENCRYPT":
            pt_in = input_in_hex[block_size_bits * i // 8: (block_size_bits * (i + 1)) // 8]
            logger.debug(f"pt_in: {pt_in.hex()}")
            block_out = Cipher(pt_in, key)
            logger.debug(f"ct_out: {block_out}")
            out += (block_out)
        else:
            ct_in = input_in_hex[block_size_bits * i // 8: (block_size_bits * (i + 1)) // 8]
            logger.debug(f"ct_in: {ct_in.hex()}")
            block_out = InvCipher(ct_in, key)
            logger.debug(f"pt_out: {block_out}")
            out += (block_out)
    logger.debug(f"output: {out}\n")
    return out

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
                chain_iv = last_block_ct[0]
            last_block_ct = _aes_cbc_encrypt(pt_in, key, chain_iv)
            logger.debug(f"ct_out: {last_block_ct[0]}")
            out += (last_block_ct[0])
        else:
            ct_in = input_in_hex[block_size_bits * i // 8: (block_size_bits * (i + 1)) // 8]
            logger.debug(f"ct_in: {ct_in}")
            if i == 0:
                chain_iv = iv
                last_block_ct = ct_in
            else:
                chain_iv = last_block_ct.hex()
            block_out = _aes_cbc_decrypt(ct_in, key, chain_iv)
            logger.debug(f"pt_out: {block_out[0]}")
            out += (block_out[0])
            last_block_ct = ct_in
    logger.debug(f"output: {out}\n")
    return out

def _aes_cbc_encrypt(plaintext: bytes, key: str, chain_iv: str):
    chain_iv_hex = bytes.fromhex(chain_iv)

    input = bytes(a ^ b for a, b in zip(plaintext, chain_iv_hex))
    output = Cipher(input, key)
    ciphertext = output
    
    return ciphertext, input, output

def _aes_cbc_decrypt(ciphertext: bytes, key: str, chain_iv):
    chain_iv_hex = bytes.fromhex(chain_iv)

    input = ciphertext
    output = InvCipher(input, key)
    plaintext = bytes(a ^ b for a, b in zip(bytes.fromhex(output), chain_iv_hex))
    
    return plaintext.hex(), input, output

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logging.getLogger(__name__).setLevel(logging.DEBUG)