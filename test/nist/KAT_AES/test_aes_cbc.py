from pathlib import Path 
import pytest

from src.python.aes_modes import aes_cbc
from scripts.rsp_parser import parse_kat_file

# TODO: Support 192 and 256
kat_cbc_files = Path("nist/KAT_AES").glob("CBC*128.rsp")
print(kat_cbc_files)
@pytest.mark.parametrize("kat_files", kat_cbc_files, ids=lambda p: p.name)
def test_kat_aes_cbc_encrypt(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        if op == "ENCRYPT":
            ct = aes_cbc(value.plaintext, value.key, value.iv, op)
            assert(ct == value.ciphertext)

kat_cbc_files = Path("nist/KAT_AES").glob("CBC*128.rsp")
print(kat_cbc_files)
@pytest.mark.parametrize("kat_files", kat_cbc_files, ids=lambda p: p.name)
def test_kat_aes_cbc_decrypt(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        if op == "DECRYPT":
            pt = aes_cbc(value.ciphertext, value.key, value.iv, op)
            assert(pt == value.plaintext)