from pathlib import Path 
import pytest

from src.python.aes_modes import aes_ecb
from scripts.rsp_parser import parse_kat_file

# TODO: Support 192 and 256
def get_kat_ecb_files():
    return list(Path("nist/KAT_AES").glob("ECB*128.rsp"))

@pytest.mark.parametrize("kat_files", get_kat_ecb_files(), ids=lambda p: p.name)
def test_kat_aes_ecb_encrypt(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        if op == "ENCRYPT":
            ct = aes_ecb(value.plaintext, value.key, op)
            assert(ct == value.ciphertext)

@pytest.mark.parametrize("kat_files", get_kat_ecb_files(), ids=lambda p: p.name)
def test_kat_aes_ecb_decrypt(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        if op == "DECRYPT":
            pt = aes_ecb(value.ciphertext, value.key, op)
            assert(pt == value.plaintext)