#include <Windows.h>
#include <iostream>
#include <locale>
#include <thread>

#include "AuthHandler.hpp"
#include "SecurityChecker.hpp"
#include "EncryptionHandler.hpp"
#include "JVMHandler.hpp"
#include "skStr.h"

#pragma comment(lib, "psapi.lib")   

std::string folderPath = skCrypt("AllClassesPath").decrypt();
std::string folderPath2 = skCrypt("NativesPath").decrypt();

std::wstring stringToWstring(const std::string& str)
{
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

int main()
{
    std::locale::global(std::locale("en_US.utf8"));
    std::wcout.imbue(std::locale());
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    std::cout << "Welcome" << std::endl;
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN);

    std::string keyString = skCrypt("").decrypt();
    const unsigned char* key = reinterpret_cast<const unsigned char*>(keyString.c_str());
    
    AuthHandler auth;
    auth.Initialize();
    
    auth.Authenticate();
    
    auth.DisplaySubscription();
    
    DWORD processID = GetCurrentProcessId();
    std::thread t234234(SecurityChecker::CheckDllsRepeatedly, processID);

    SecurityChecker security;
    security.PerformIntegrityCheck(hConsole, folderPath, folderPath2);
    
    JVMHandler jvmHandler;
    jvmHandler.InitializeAndRun(hConsole, key);
    
    return 0;
}