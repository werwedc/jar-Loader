#include "AuthHandler.hpp"

auto name = skCrypt("");
auto ownerid = skCrypt("");
auto secret = skCrypt(""); 
auto version = skCrypt("1.0");
auto url = skCrypt("");

api KeyAuthApp(name.decrypt(), ownerid.decrypt(), secret.decrypt(), version.decrypt(), url.decrypt());

const std::string compilation_date = (std::string)skCrypt(DATE);
const std::string compilation_time = (std::string)skCrypt(TIME);

AuthHandler::AuthHandler() {}

void AuthHandler::Initialize() {
    std::cout << "Initializing KeyAuth" << std::endl;
    KeyAuthApp.init();
    std::string consoleTitle = (std::string)skCrypt("Loader - Built at:  ") + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    
    if (KeyAuthApp.checkblack()) {
        abort();
    }
}

void AuthHandler::Authenticate() {
    std::cout << "Authenticating" << std::endl;
    if (!KeyAuthApp.data.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
        exit(0);
    }
    if (std::filesystem::exists("test.json"))
    {
        if (!CheckIfJsonKeyExists("test.json", "username"))
        {
            std::string key = ReadFromJson("test.json", "license");
            KeyAuthApp.license(key);
            if (!KeyAuthApp.data.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
                exit(0);
            }
            std::cout << skCrypt("Successfully Automatically Logged In\n");
        }
        else
        {
            std::string username = ReadFromJson("test.json", "username");
            std::string password = ReadFromJson("test.json", "password");
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.data.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
                Sleep(1500);

                exit(0);
            }
            std::cout << skCrypt("Successfully Automatically Logged In\n");
        }
    }
    else
    {
        std::string key;
        std::cout << skCrypt("\n Enter license: ");
        std::cin >> key;
        KeyAuthApp.license(key);

        if (!KeyAuthApp.data.success)
        {
            std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
            Sleep(1500);
            exit(0);
        }

        WriteToJson("test.json", "license", key, false, "", "");
        std::cout << skCrypt("Successfully Created File For Auto Login");
    }
}

void AuthHandler::DisplaySubscription() {
    for (int i = 0; i < KeyAuthApp.data.subscriptions.size(); i++) {
        auto sub = KeyAuthApp.data.subscriptions.at(i);
        std::cout << skCrypt("Client till: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
    }
}

std::string AuthHandler::tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

    return std::string(buffer);
}

std::time_t AuthHandler::string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

std::tm AuthHandler::timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}