# AES
The goal of this project is to explore co-simulation of python and systemverilog using AES cores as an example. AES Cores will be created and tested in python followed by systemverilog. Cocotb will be used as a bridge between the python and systemverilog for stimulus and scoreboarding. 

![CI](https://github.com/bjohnsonfl/aes/actions/workflows/python-app.yaml/badge.svg?branch=main)

Docs:
- AES Spec
    * https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427
- AES Modes
    * https://csrc.nist.gov/Projects/block-cipher-techniques/BCM
    * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

IUT Tests:
Nist Test vectors
* https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#AES

```
./scripts/download_nist.sh
python3 -m pip install pycryptodome pytest
PYTHONPATH=src pytest
```



