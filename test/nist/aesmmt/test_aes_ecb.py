from pathlib import Path 
import pytest

from src.python.aes_modes import aes_ecb
from scripts.rsp_parser import parse_kat_file

def get_mmt_ecb_files():
    return list(Path("nist/aesmmt").glob("ECB*.rsp"))

@pytest.mark.parametrize("mmt_files", get_mmt_ecb_files(), ids=lambda p: p.name)
def test_mmt_aes_ecb_encrypt(mmt_files):
    mmt_list = parse_kat_file(mmt_files)
    for (op, count), value in mmt_list.items():
        if op == "ENCRYPT":
            print(f"ENCRYPT: {count}")
            ct = aes_ecb(value.plaintext, value.key, op)
            assert(ct == value.ciphertext)

@pytest.mark.parametrize("mmt_files", get_mmt_ecb_files(), ids=lambda p: p.name)
def test_mmt_aes_ecb_decrypt(mmt_files):
    mmt_list = parse_kat_file(mmt_files)
    for (op, count), value in mmt_list.items():
        if op == "DECRYPT":
            print(f"DECRYPT: {count}")
            pt = aes_ecb(value.ciphertext, value.key, op)
            assert(pt == value.plaintext)