#ifndef CRYPTO
#define CRYPTO

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

RSA *createRSA(unsigned char *key, int publicKey);
RSA *createRSAWithFilename(const char* filename, int publicKey);
int RSA_public_encrypt_data(unsigned char *data, int data_len, char *keyFile, unsigned char *encrypted);
int RSA_private_encrypt_data(unsigned char *data, int data_len, char *keyFile, unsigned char *encrypted);
int RSA_public_decrypt_data(unsigned char *enc_data, int data_len, char *keyFile, unsigned char *decrypted);
int RSA_private_decrypt_data(unsigned char * enc_data, int data_len, char *keyFile, unsigned char *decrypted);

int generateRandomNumber(unsigned char *buffer, int bytes);
int pem_pass_cb(char *buf, int size, int rwflag, void *u);

#endif // CRYPTO

