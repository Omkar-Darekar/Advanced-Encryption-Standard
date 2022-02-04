# Advanced-Encryption-Standard
The Advanced Encryption Standard, also known by its original name Rijndael, is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology in 2001.

Please refer Advanced Encryption Standard (AES) (https://www.geeksforgeeks.org/advanced-encryption-standard-aes/) to get theoretical idea of how AES algorithm works. This is a AES code example referred from https://github.com/ceceww/aes.git.

This article consist of AES implementation for 128 bit encryption. Code consist of following files

        main.cpp
        AES_EncryptionDecryption.h
        AES_EncryptionDecryption.cpp
        structures.h
        keyfile




**Code Testing Report -**

**System Configuration –  **

    Edition:  Windows 11 Pro

    Version:  21H2

    Processor: Intel(R) Core (TM) i7-7700 CPU @ 3.60GHz   3.60 GHz

    Installed RAM: 16.0 GB  

    System type: 64-bit operating system, x64-based processor

    Software Tool: Microsoft Visual Studio Professional 2022 (64-bit) Version 17.0.5

    Compiler: ISO C++14 Standard


**Code have tested on following parameters –**

        Experiment No.     String Size (bytes)      Iteration Count         Encryption Time (Sec)            Decryption Time (Sec)

        1.                   1024                       1000                      0.001509                          0.0016

        2.                   2048                       1000                      0.000072                          0.000066

        3.                   3072                       1000                      0.000134                          0.000112

        4.                   4096                       1000                      0.00017                           0.000148

        5.                   5120                       1000                       0.000172                         0.000187

        6.                   6144                       1000                       0.000276                         0.000293

        7.                   7168                       1000                        0.000331                        0.000322

        8.                   8196                       1000                        0.00038                          0.000366

        9.                   9216                       1000                        0.000425                         0.000408

        10.                  10240                      1000                        0.000513                          0.000488

        11.                  20480                      1000                        0.000807                          0.000812

        12.                  20480                      10000                       0.0007063                         0.000698



**This code also work on LINUX environment. To compile and run on LINUX environment -**
  g++ main.cpp AES_EncryptionDecryption.cpp -o main
  ./main

**Output - **

        Input string : bpurmplcfmgxcsa
        Encrypted message in hex : a 30 8 c5 c2 da 69 21 e7 39 ac cb 6 8 8f 85
        Decrypted Message : bpurmplcfmgxcsa
        EncyptionTime : 0.00018
        DecryptionTime : 0.00013
