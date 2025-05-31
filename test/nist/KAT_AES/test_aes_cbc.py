from pathlib import Path 
import pytest
import re

from src.python.aes_modes import aes_cbc
from scripts.rsp_parser import parse_kat_file

# TODO: Support 192 and 256
def get_kat_cbc_files():
    return list(Path("nist/KAT_AES").glob("CBC*128.rsp"))

@pytest.mark.parametrize("kat_files", get_kat_cbc_files(), ids=lambda p: p.name)
def test_kat_aes_cbc_encrypt(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        if op == "ENCRYPT":
            ct = aes_cbc(value.plaintext, value.key, value.iv, op)
            assert(ct == value.ciphertext)

            # Swap PT and IV
            ct = aes_cbc(value.iv, value.key, value.plaintext, op)
            assert(ct == value.ciphertext)


@pytest.mark.parametrize("kat_files", get_kat_cbc_files(), ids=lambda p: p.name)
def test_kat_aes_cbc_decrypt(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        if op == "DECRYPT":
            pt = aes_cbc(value.ciphertext, value.key, value.iv, op)
            assert(pt == value.plaintext)

            # Swap CT and IV
            pt = aes_cbc(value.ciphertext, value.key, value.plaintext, op)
            assert(pt == value.iv)