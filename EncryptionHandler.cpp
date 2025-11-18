#include "EncryptionHandler.hpp"

void EncryptionHandler::encryptFile(const std::string& fileName, const byte* key)
{
    std::ifstream inputFile(fileName, std::ios::binary | std::ios::ate);

    if (!inputFile.is_open()) {
        std::cerr << "Error opening file: " << fileName << std::endl;
        return;
    }
    
    size_t fileSize = static_cast<size_t>(inputFile.tellg());
    inputFile.seekg(0, std::ios::beg);

    std::vector<byte> fileContent(fileSize);
    inputFile.read(reinterpret_cast<char*>(fileContent.data()), fileSize);
    inputFile.close();

    byte iv[AES::BLOCKSIZE];
    memset(iv, 0x00, AES::BLOCKSIZE);

    CBC_Mode<AES>::Encryption encryption(key, AES::DEFAULT_KEYLENGTH, iv);

    ArraySource(fileContent.data(), fileContent.size(), true,
        new StreamTransformationFilter(encryption,
            new FileSink(fileName.c_str(), std::ios::binary), StreamTransformationFilter::PKCS_PADDING
        )
    );
}

void EncryptionHandler::decryptData(const byte* encryptedData, size_t dataSize, const byte* key, byte*& decryptedData, size_t& decryptedSize)
{
    byte iv[AES::BLOCKSIZE];
    memset(iv, 0x00, AES::BLOCKSIZE);

    CBC_Mode<AES>::Decryption decryption(key, AES::DEFAULT_KEYLENGTH, iv);
    decryptedSize = dataSize;
    decryptedData = new byte[decryptedSize];

    ArraySource(encryptedData, dataSize, true,
        new StreamTransformationFilter(decryption,
            new ArraySink(decryptedData, decryptedSize)
        )
    );

    size_t paddingSize = static_cast<size_t>(decryptedData[decryptedSize - 1]);
    if (paddingSize <= decryptedSize) {
        decryptedSize -= paddingSize;
    }
    else {
        std::cerr << "Invalid padding size!" << std::endl;
    }
}

void EncryptionHandler::writeBytesToFile(const byte* data, size_t dataSize, const std::string& fileName) {
    std::ofstream outputFile(fileName, std::ios::binary | std::ios::trunc);
    if (!outputFile.is_open()) {
        std::cerr << "Error opening output file: " << fileName << std::endl;
        return;
    }
    outputFile.write(reinterpret_cast<const char*>(data), dataSize);

    outputFile.close();
}