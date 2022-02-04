//AES_EncryptionDecryption.h

/*
* Author :	Omkar Darekar
* Date	 :	21-01-2022
* Github :	https://github.com/Omkar-Darekar
* StackOverflow : https://stackoverflow.com/users/12214121/omkar
* Code refered from : https://github.com/ceceww/aes
*/

#pragma once

#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>

using namespace std;

class AES_Encyption {
private:
	void AddRoundKey(unsigned char* state, unsigned char* roundKey);
	void SubBytes(unsigned char* state);
	void ShiftRows(unsigned char* state);
	void MixColumns(unsigned char* state);
	void Round(unsigned char* state, unsigned char* key);
	void FinalRound(unsigned char* state, unsigned char* key);
	void AESEncrypt(unsigned char* message, unsigned char* expandedKey, unsigned char* encryptedMessage);

public:
	AES_Encyption();
	//unsigned char* AES_EncryptionBegins(char* message, int originalLen, unsigned char* key);
	unsigned char* AES_EncryptionBegins(char* message, int* originalLen, unsigned char* key);
};

class AES_Decryption {
private:
	void SubRoundKey(unsigned char* state, unsigned char* roundKey);
	void InverseMixColumns(unsigned char* state);
	void ShiftRows(unsigned char* state);
	void SubBytes(unsigned char* state);
	void Round(unsigned char* state, unsigned char* key);
	void InitialRound(unsigned char* state, unsigned char* key);
	void AESDecrypt(unsigned char* encryptedMessage, unsigned char* expandedKey, unsigned char* decryptedMessage);
	
public:
	char DecryptedMessage[16] = { "\0" };
	AES_Decryption();
	//void AES_DecryptionBegins(unsigned char* ucEncryptedMessages, int paddedMessageLen, unsigned char* key);
	void AES_DecryptionBegins(unsigned char* ucEncryptedMessages, unsigned char* key);
};

