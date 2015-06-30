#include "crypto.h"

RSA *createRSA(unsigned char *key, int publicKey)
{
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL) {
        printf( "Failed to create key BIO");
        return 0;
    }

    if (publicKey) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    return rsa;
}

RSA *createRSAWithFilename(const char *filename, int publicKey)
{
    FILE * fp = fopen(filename,"rb");

    if (fp == NULL) {
        printf("Unable to open file %s \n",filename);
        return NULL;
    }

    RSA *rsa = NULL;

    if (publicKey) {
        PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    } else {
        PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    }

    fclose(fp);
    return rsa;
}

static const int padding = RSA_PKCS1_PADDING;

//int RSA_public_encrypt_data(unsigned char *data, int data_len, char *keyFile, unsigned char *encrypted)
//{
//    RSA * rsa = createRSAWithFilename(keyFile, 1);
//    if (rsa == NULL) {
//        return 1;
//    }
//    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
//    return result;
//}

//int RSA_private_encrypt_data(unsigned char *data, int data_len, char *keyFile, unsigned char *encrypted)
//{
//    RSA * rsa = createRSAWithFilename(keyFile, 0);
//    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
//    return result;
//}

//int RSA_public_decrypt_data(unsigned char *enc_data, int data_len, char *keyFile, unsigned char *decrypted)
//{
//    RSA * rsa = createRSAWithFilename(keyFile, 1);
//    int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
//    return result;
//}

//int RSA_private_decrypt_data(unsigned char * enc_data, int data_len, char *keyFile, unsigned char *decrypted)
//{
//    RSA * rsa = createRSAWithFilename(keyFile, 0);
//    if (rsa == NULL) {
//        return 1;
//    }
//    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
//    return result;
//}

int generateRandomNumber(unsigned char *buffer, int bytes)
{
    if (buffer == NULL) {
        return -1;
    }

    int ret = RAND_bytes(buffer, bytes);

    if (ret != 1) {
        return -2;
    }
    return 0;
}

int pem_pass_cb(char *buf, int size, int rwflag, void *u) {
    int len;

    /* get pass phrase, length 'len' into 'tmp' */
    len = strlen((char*)u);

    if (len <= 0) return 0;

    /* if too long, truncate */
    if (len > size) len = size;
    memcpy(buf, (char*)u, len);
    return len;
}
