#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

class EncryptionHandler {
public:
    void encryptFile(const std::string& fileName, const byte* key);
    void decryptData(const byte* encryptedData, size_t dataSize, const byte* key, byte*& decryptedData, size_t& decryptedSize);
    void writeBytesToFile(const byte* data, size_t dataSize, const std::string& fileName);
};