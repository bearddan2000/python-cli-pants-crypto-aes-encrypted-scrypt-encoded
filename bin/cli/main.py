#!/usr/bin/env python
import pyscrypt
import sys
from compression import AESCipher

def encryptAlg(aes, password):
    return aes.encrypt(password)

def hashPsw(aes, password):
    encryptedStr = encryptAlg(aes, password)
    salt = b'aa1f2d3f4d23ac44e9c5a6c3d8f9ee8c'
    key = pyscrypt.hash(encryptedStr, salt, 2048, 8, 1, 32)
    return key.hex()

def comp_hash(aes, psw1, psw2):
    hash1 = hashPsw(aes, psw1)
    hash2 = hashPsw(aes, psw2)
    print( "[COMP_HASH] psw1 = %s, psw2 = %s" % (psw1, psw2));
    if hash1 == hash2:
        print( "[COMP] true");
    else:
        print( "[COMP] false");

def printPsw(aes, password):
    print( "[INPUT] %s" % password);
    print( "[OUTPUT] %s" % hashPsw(aes, password));

def main():
    aes = AESCipher()
    psw1 = 'pass123';
    psw2 = '123pass';
    printPsw(aes, psw1)
    printPsw(aes, psw2)
    comp_hash(aes, psw1, psw1)
    comp_hash(aes, psw1, psw2)

if __name__ == '__main__':
    main()
