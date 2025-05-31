#!/bin/bash
dir="nist"

if [ ! -d "$dir/KAT_AES" ]; then
    mkdir -p $dir/KAT_AES 
    curl -L -o $dir/KAT_AES.zip "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip"
    unzip $dir/KAT_AES.zip -d $dir/KAT_AES
fi

if [ ! -d "$dir/aesmmt" ]; then
    mkdir -p $dir/aesmmt 
    curl -L -o $dir/aesmmt.zip "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip"
    unzip $dir/aesmmt.zip -d $dir/aesmmt
fi