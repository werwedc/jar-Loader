#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <psapi.h>
#include <openssl/sha.h>
#include "skStr.h"
#include "auth.hpp" 

class SecurityChecker {
public:
    static void CheckWindowTitlesRepeatedly(DWORD processID);
    void PerformIntegrityCheck(HANDLE hConsole, std::string folderPath, std::string folderPath2);
    int countFilesInTree(const std::string& folderPath);

private:
    std::string calculateSHA256(const std::string& filePath);
    
    static void processFiles(const std::vector<std::string>& files, int threadID, std::vector<std::string>& fileHashes, HANDLE hConsole);
};