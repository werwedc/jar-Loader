#include "JVMHandler.hpp"

bool JVMHandler::LoadClass(JNIEnv* env, jobject classLoader, const std::string& filePath, const unsigned char* key, EncryptionHandler& encryption) {
    FILE* file = fopen(filePath.c_str(), "rb");
    if (!file) return false;

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    std::vector<byte> byteBuffer(fileSize);
    fread(byteBuffer.data(), 1, fileSize, file);
    fclose(file);

    byte* decryptedData = nullptr;
    size_t decryptedSize = 0;
    
    encryption.decryptData(byteBuffer.data(), fileSize, key, decryptedData, decryptedSize);

    if (decryptedData) {
        // Define the class in the JVM
        jclass defined = env->DefineClass(NULL, classLoader, (jbyte*)decryptedData, decryptedSize);
        
        delete[] decryptedData;
        
        if (env->ExceptionCheck()) {
            env->ExceptionClear(); 
            return false;
        }
        return defined != nullptr;
    }
    return false;
}

void JVMHandler::InitializeAndRun(HANDLE hConsole, const unsigned char* key) {
    EncryptionHandler encryption;
    
    int mem = 1024;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
    std::cout << std::endl << "Enter the amount of memory(in megabytes)" << std::endl;
    std::cin >> mem;
    
    std::string memS = "-Xmx" + std::to_string(mem) + "m";
    
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN);
    
    JavaVM* jvm;
    JNIEnv* env;
    JavaVMInitArgs vm_args;
    JavaVMOption* options = new JavaVMOption[4];
    options[0].optionString = const_cast<char*>("-Djava.class.path=C:\\werwedc\\classesDev");
    options[1].optionString = const_cast<char*>("-Djava.library.path=C:\\werwedc\\natives");
    options[2].optionString = const_cast<char*>("-Xverify:none");
    options[3].optionString = const_cast<char*>(memS.c_str());

    vm_args.version = JNI_VERSION_10;
    vm_args.nOptions = 4; 
    vm_args.options = options;
    vm_args.ignoreUnrecognized = false;

    jint ret = JNI_CreateJavaVM(&jvm, (void**)&env, &vm_args);

    jclass loader = env->FindClass("java/lang/ClassLoader");
    jmethodID getClassLoaderId = env->GetStaticMethodID(loader, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject classLoader = env->CallStaticObjectMethod(loader, getClassLoaderId);
    
    std::cout << "Loading classes..." << std::endl;

    // We need to load parent classes first
    std::vector<std::string> priorityClasses = {
        skCrypt("Example1.class").decrypt(),
        skCrypt("Example2.class").decrypt(),
        skCrypt("Example3.class").decrypt(),
        skCrypt("Example4.class").decrypt(),
        skCrypt("Example5.class").decrypt(),
        skCrypt("Example6.class").decrypt(),
        skCrypt("Example7.class").decrypt()
    };

    std::set<std::string> loadedPaths;

    for (const auto& path : priorityClasses) {
        if (LoadClass(env, classLoader, path, key, encryption)) {
            try {
                loadedPaths.insert(std::filesystem::path(path).string());
            } catch (...) {
                loadedPaths.insert(path);
            }
        }
    }

    // Load remaining classes
    std::string scanPath = skCrypt("ClassesYouWishToEncryptPath").decrypt();
    
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(scanPath)) {
            if (std::filesystem::is_regular_file(entry)) {
                std::string filePath = entry.path().string();

                if (filePath.find(".class") == std::string::npos) {
                    continue;
                }

                // Check if already loaded by the parent classes mechanism
                if (loadedPaths.find(filePath) != loadedPaths.end()) {
                    continue; 
                }

                LoadClass(env, classLoader, filePath, key, encryption);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error iterating directory: " << e.what() << std::endl;
    }

    std::cout << "Trying to find Start class..." << std::endl;
    jclass StartClass = env->FindClass(skCrypt("Start").decrypt());
    
    std::cout << "Running..." << std::endl;
    if (StartClass != nullptr) {
        jmethodID mid = env->GetStaticMethodID(StartClass, "main", "([Ljava/lang/String;)V");
        if (mid != nullptr) {
            jobjectArray args = env->NewObjectArray(1, env->FindClass("java/lang/String"), NULL);
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
            env->CallStaticVoidMethod(StartClass, mid, args);
        }
    }

    std::cout << skCrypt("\n\n Closing in five seconds...");
    Sleep(5000);
    exit(0);
}