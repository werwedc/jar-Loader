#pragma once
#include "auth.hpp"
#include "skStr.h"
#include <string>
#include <iostream>
#include <ctime>
#include "utils.hpp"

using namespace KeyAuth;

class AuthHandler {
public:
    AuthHandler();
    void Initialize();
    void Authenticate();
    void DisplaySubscription();
    
private:
    std::string tm_to_readable_time(tm ctx);
    static std::time_t string_to_timet(std::string timestamp);
    static std::tm timet_to_tm(time_t timestamp);
};