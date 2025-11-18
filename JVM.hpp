#pragma once
#include <jni.h>
#include <string>
#include <iostream>
#include <vector>
#include <filesystem>
#include <set>
#include <Windows.h>
#include "skStr.h"
#include "EncryptionHandler.hpp"

class JVMHandler {
public:
    void InitializeAndRun(HANDLE hConsole, const unsigned char* key);

private:
    bool LoadClass(JNIEnv* env, jobject classLoader, const std::string& filePath, const unsigned char* key, EncryptionHandler& encryption);
};