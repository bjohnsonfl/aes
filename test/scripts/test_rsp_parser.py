import logging
import pytest
from pathlib import Path 
from scripts.aes import aes_cbc, aes_ecb
from scripts.rsp_parser import parse_kat_file

logger = logging.getLogger(__name__)
###########
# KAT Tests
###########
def get_kat_ecb_files():
    return list(Path("nist/KAT_AES").glob("ECB*.rsp"))

@pytest.mark.parametrize("kat_files", get_kat_ecb_files(), ids=lambda p: p.name)
def test_kat_aes_ecb(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        aes_ecb(op, value.key, value.iv, value.plaintext, value.ciphertext)

def get_kat_cbc_files():
    return list(Path("nist/KAT_AES").glob("CBC*.rsp"))

@pytest.mark.parametrize("kat_files", get_kat_cbc_files(), ids=lambda p: p.name)
def test_kat_aes_cbc(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        aes_cbc(op, value.key, value.iv, value.plaintext, value.ciphertext)

###########
# MMT Tests
###########

def get_mmt_ecb_files():
    return list(Path("nist/aesmmt").glob("ECB*.rsp"))

@pytest.mark.parametrize("kat_files", get_mmt_ecb_files(), ids=lambda p: p.name)
def test_mmt_aes_ecb(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        aes_ecb(op, value.key, value.iv, value.plaintext, value.ciphertext)

def get_mmt_cbc_files():
    return list(Path("nist/aesmmt").glob("CBC*.rsp"))

@pytest.mark.parametrize("kat_files", get_mmt_cbc_files(), ids=lambda p: p.name)
def test_mmt_aes_cbc(kat_files):
    kat_list = parse_kat_file(kat_files)
    for (op, count), value in kat_list.items():
        aes_cbc(op, value.key, value.iv, value.plaintext, value.ciphertext)