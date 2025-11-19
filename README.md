# Secure JNI Bootstrapper
A native C++ loader designed to solve the problem of the ease with which Java classes can be decompiled. 
This project showcases usage of Java Native Interface and anti-tampering mechanisms. 
Though these measures, as any other can be bypassed, every failed attempt and triggered security check invalidates the key used, and blacklists the attackers HWID and IP.
This forces the attacker to burn many keys, making this a viable strategy for less popular software.
### Authentication 
Uses a cloud-based licensing API. Currently, this project uses KeyAuth, a popular open-source library. 
Note: also have developed "Keystone", a licensing solution operating on the same principles. 
- Hardware locking: one license is tied to a HWID on the first activation to prevent account sharing. 
- Blacklist check upon initialization: IPs and HWIDs can be verified
- Credentials are saved in a json file after the first successful login
- After the login, the program displays the status of the subscription - how many days are left.
### Anti-tamper
Implements "Defence in Depth" to make reverse engineering costly. 
- Multithreaded SHA-256 hashing of the Java paths and native libraries. Mismatch triggers session termination and blacklisting. 
- Monitoring of the window titles to detect popular analysis tools. 
### JVM Handling
- The user can choose the amount of memory to allocate. Then, using 'JNI_CreateJavaVM' JVM is created with the desired arguments passed.
- Then, the bootstrapper reads the AES-encrypted .class files from the disk. It then decrypts them in memory and defines them in the JVM. This way, decrypted java classes never touch the disk.
  (Note: This architecture necessitates that proper memory protection for the bootstrapper and JVM is implemented to prevent dumping in runtime)

### Tech stack used:
- C++ 17
- CryptoPP and OpenSSL
- JNI, Java 17
