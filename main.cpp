/*
* Author :	Omkar Darekar
* Date	 :	21-01-2022
* Github :	https://github.com/Omkar-Darekar
* StackOverflow : https://stackoverflow.com/users/12214121/omkar
* Code refered from : https://github.com/ceceww/aes
*/

// main.cpp

//#define _CRT_SECURE_NO_DEPRECATE
#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <time.h>
#include<Windows.h>
#include"AES_EncryptionDecryption.h"

#define MAXSIZE 15 //This should not change
#define MAX_SIZE_OF_INPUT_STRING (1024*1)
using namespace std;
clock_t tStart;
int main(void) {
	AES_Encyption* encrypt = new AES_Encyption();
	AES_Decryption* decrypt = new AES_Decryption();
	if (encrypt == NULL || decrypt == NULL) {
		cout << "Out of memory.\n";
		return 0;
	}

	// Read in the key
	unsigned char key[16]{};
	
	{
		string sKeyString;
		ifstream keyfile;
		keyfile.open("keyfile", ios::in | ios::binary);
		if (keyfile.is_open()) {
			getline(keyfile, sKeyString); // The first line of file should be the key
			cout << "\nRead in the 128-bit key from keyfile" << endl;
			keyfile.close();
		}
		else {
			cout << "Unable to open KEY file";
			exit(0);
		}

		int i = 0;
		unsigned int c;
		istringstream hex_chars_stream(sKeyString);
		while (hex_chars_stream >> hex >> c) {
			key[i] = c;
			i++;
		}
	}

	long int itr = 0;
	double EncyptionTime = 0.0;
	double DecryptionTime = 0.0;
	char cch;
	int i = 0;

	while (itr < 100) {
		itr++;
		{
			int ii = 0;
			char message[MAX_SIZE_OF_INPUT_STRING] = { "\0" };
			for (ii = 0; ii < MAX_SIZE_OF_INPUT_STRING-1; ii++) {
				cch = 'a' + rand() % 24;
				message[ii] = cch;
			}
			message[ii] = '\0';

			i = 0;
			while (message[i] != '\0') {
				{
					char SendingArray[MAXSIZE] = { "\0" };
					for (int j = 0; j < MAXSIZE; j++, i++) {
						if (message[i] == '\0')	break;
						SendingArray[j] = message[i];
					}

					printf("\nInput string : %s\n", SendingArray); 
					
					tStart = clock();
					int iMessageLength = static_cast<int>(strlen(SendingArray));
					unsigned char* encryptedMessage = encrypt->AES_EncryptionBegins(SendingArray, &iMessageLength, key);
					EncyptionTime += ((double)(clock() - tStart) / CLOCKS_PER_SEC);

					int messageLen = static_cast<int>(strlen((char*)encryptedMessage));

					cout << "Encrypted message in hex : ";
					for (int i = 0; i < iMessageLength; i++) {
						cout << hex << (int)encryptedMessage[i] << " ";
					}

					tStart = clock();
					decrypt->AES_DecryptionBegins(encryptedMessage, key);
					DecryptionTime += ((double)(clock() - tStart) / CLOCKS_PER_SEC);

					//Freeing the memory
					delete[] encryptedMessage;

					cout << "\nDecrypted Message : " << decrypt->DecryptedMessage << endl;
					/*if (strcmp(decrypt->DecryptedMessage, SendingArray) != 0) {
						cout << "Not equal \n";
					}*/
				}
			}
		}
	}

	cout << "EncyptionTime : " << (EncyptionTime / itr) << endl;
	cout << "DecryptionTime : " << (DecryptionTime / itr) << endl;

	return 0;
}