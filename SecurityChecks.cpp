#include "SecurityChecker.hpp"
#include "auth.hpp" 
#include <fstream>
#include <iomanip>

extern KeyAuth::api KeyAuthApp;

constexpr int NUM_THREADS = 4;

std::string toLowerCase(const std::string& input) {
    std::string result = input;
    for (char& c : result) {
        c = std::tolower(c);
    }
    return result;
}

// Blacklist
const std::vector<std::string> PROHIBITED_TITLES = {
    skCrypt("injector").decrypt(),
    skCrypt("decompiler").decrypt(),
    skCrypt("recaf").decrypt(),
    skCrypt("deobfuscator").decrypt(),
    skCrypt("debugger").decrypt(),
    skCrypt("fiddler").decrypt(),
    skCrypt("bytecode").decrypt(),
    skCrypt("hacker").decrypt(),
    skCrypt("v8.3").decrypt(),
    skCrypt("inject").decrypt()
};

BOOL CALLBACK SecurityChecker::EnumWindowsCallback(HWND hwnd, LPARAM lParam)
{
    char buffer[128];
    if (GetWindowTextA(hwnd, buffer, sizeof(buffer)) == 0) return TRUE;

    std::string title = buffer;
    std::transform(title.begin(), title.end(), title.begin(), ::tolower);
    
    for (const auto& prohibited : PROHIBITED_TITLES) {
        if (title.find(prohibited) != std::string::npos) {
            std::cout << skCrypt("\n[!] Window name detection triggered: ") << prohibited << std::endl;
            KeyAuthApp.ban();
            exit(0);
        }
    }
    return TRUE;
}

void SecurityChecker::CheckWindowTitlesRepeatedly(DWORD processID)
{
    while (true)
    {
        EnumWindows(SecurityChecker::EnumWindowsCallback, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

std::string SecurityChecker::calculateSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return ""; 
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::string fileHash;
    fileHash.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        fileHash += buf;
    }

    return fileHash;
}

void SecurityChecker::processFiles(const std::vector<std::string>& files, int threadID, std::vector<std::string>& fileHashes, HANDLE hConsole) {
    for (size_t i = threadID; i < files.size(); i += NUM_THREADS) {
        std::string filePath = files[i];
        std::string fileHash = calculateSHA256(filePath);
        
        if (!fileHash.empty()) {
            fileHashes[i] = fileHash;
        }

        int currentCount = ++processedFiles;
        if (currentCount % 10 == 0 || currentCount == totalFiles) {
            std::lock_guard<std::mutex> lock(consoleMutex); 
            
            float progress = (float)currentCount / (float)totalFiles * 100.0f;
            
            std::cout << "\r[+] Verifying Integrity: " 
                      << std::fixed << std::setprecision(1) << progress << "% [" 
                      << currentCount << "/" << totalFiles << "]" << std::flush;
        }
    }
}

int SecurityChecker::countFilesInTree(const std::string& folderPath) {
    int fileCount = 0;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(folderPath)) {
            if (std::filesystem::is_regular_file(entry)) {
                fileCount++;
            }
        }
    } catch (...) {} 
    return fileCount;
}

void SecurityChecker::PerformIntegrityCheck(HANDLE hConsole, const std::string& folderPath, const std::string& folderPath2) {
    std::cout << skCrypt("[+] gathering file system information...") << std::endl;

    std::vector<std::string> files;
    
    std::vector<std::string> pathsToCheck = {
        folderPath,
        folderPath2,
        skCrypt("C:\\jdk-17.0.2").decrypt()
    };

    for (const auto& path : pathsToCheck) {
        try {
            if (std::filesystem::exists(path)) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
                    if (std::filesystem::is_regular_file(entry)) {
                        files.push_back(entry.path().string());
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "\n[!] Warning: Could not access path " << path << ": " << e.what() << std::endl;
        }
    }

    totalFiles = files.size();
    processedFiles = 0; 

    if (totalFiles == 0) {
        std::cout << skCrypt("\n[!] No files found to verify.") << std::endl;
        return;
    }

    std::vector<std::string> fileHashes(files.size());
    std::vector<std::thread> threads;

    // Spawn threads
    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back(&SecurityChecker::processFiles, this, std::ref(files), i, std::ref(fileHashes), hConsole);
    }

    for (std::thread& thread : threads) {
        if (thread.joinable()) thread.join();
    }
    std::cout << std::endl << skCrypt("[+] Hashing complete. Verifying signature...") << std::endl;

    SHA256_CTX combinedSha256;
    SHA256_Init(&combinedSha256);

    for (size_t i = 0; i < files.size(); i++) {
        if (!fileHashes[i].empty()) {
            SHA256_Update(&combinedSha256, fileHashes[i].c_str(), fileHashes[i].length());
        }
    }

    unsigned char combinedHash[SHA256_DIGEST_LENGTH];
    SHA256_Final(combinedHash, &combinedSha256);
    
    std::string combinedHashString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", combinedHash[i]);
        combinedHashString += buf;
    }

    if (combinedHashString != skCrypt("").decrypt()) {
        std::cout << skCrypt("[!] Integrity Violation Detected.") << std::endl;
        KeyAuthApp.ban();
        abort();
        exit(0);
    } else {
        std::cout << skCrypt("[+] Integrity Check Passed.") << std::endl;
    }
}