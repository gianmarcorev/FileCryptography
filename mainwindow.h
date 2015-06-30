#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include <QProcess>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <math.h>
#include <string.h>
#include <stdio.h>
//#include <stdlib.h>

#include "crypto.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButtonRsaPublicKey_clicked();

    void on_pushButtonRsaPrivateKey_clicked();

    void on_pushButtonInputFile_clicked();

    void on_pushButtonOutputFile_clicked();

    void on_radioButtonRsaPrivateKey_clicked();

    void on_radioButtonRsaPublicKey_clicked();

    void on_pushButtonRsaEncrypt_clicked();

    void on_pushButtonRsaDecrypt_clicked();

    void on_pushButtonGenerateKey_clicked();

    void on_pushButtonGenerateIV_clicked();

    void on_pushButtonSymmetricEncrypt_clicked();

    void on_comboBoxMode_currentIndexChanged(int index);

    void on_pushButtonSymmetricDecrypt_clicked();

    void on_pushButtonGenerateIV_2_clicked();

    void on_pushButtonRsaPublicKey_2_clicked();

    void on_pushButtonSymmetricEncrypt_2_clicked();

    void on_pushButtonSelectKey_clicked();

    void on_pushButtonSaveKey_clicked();

    void on_pushButtonSymmetricDecrypt_2_clicked();

    void on_comboBoxMode_2_currentIndexChanged(int index);

private:
    void initOpenSsl();
    void handleErrors();
    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
    void updateRsaKeyMode();
    void runRsaOperation(int operation, int key_type);
    void prepareSymmetricOperation(int operation);
    void runSymmetricOperation(int operation,
                               int cipher, int mode, unsigned char *key,
                               unsigned char *iv);
    void encryptSymmetric(int operation, int cipher, int mode, unsigned char *key,
                          unsigned char *iv);
    void decryptSymmetric(int operation, int cipher, int mode, unsigned char *key,
                          unsigned char *iv);
    int getKeyLength(int cipher);
    int getIvLength(int cipher);
    int getCipherFromUi();
    int getModeFromUi();
    int getCipherFromUi2();
    int getModeFromUi2();
    EVP_CIPHER* getEvpCipher(int cipher, int mode);
    int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
        unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
        unsigned char *ciphertext);
    int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
        unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
        unsigned char *plaintext);

    Ui::MainWindow *ui;
    int mRSAKeyType;

    enum Cipher {
        CIPHER_DES = 1,
        CIPHER_3DES2,
        CIPHER_3DES3,
        CIPHER_AES128,
        CIPHER_AES192,
        CIPHER_AES256,
        CIPHER_RSA
    };

    enum BlockMode {
        MODE_CBC = 1,
        MODE_ECB,
        MODE_CFB,
        MODE_OFB
    };

    enum Operation {
        ENCRYPT = 1,
        DECRYPT
    };

    enum RsaKeyType {
        RSA_PUBLIC_KEY = 1,
        RSA_PRIVATE_KEY
    };
};

#endif // MAINWINDOW_H
