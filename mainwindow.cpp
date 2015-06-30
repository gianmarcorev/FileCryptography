#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    mRSAKeyType = RSA_PUBLIC_KEY;
    updateRsaKeyMode();
    on_comboBoxMode_currentIndexChanged(0);
    on_comboBoxMode_2_currentIndexChanged(0);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButtonInputFile_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open file"), "/home/gianmarco/Desktop", tr("All files (*.*)"));
    if(!fileName.isEmpty()) {
        ui->lineEditInputFile->setText(fileName);
    }
}

void MainWindow::on_pushButtonOutputFile_clicked()
{
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save file"), "/home/gianmarco/Desktop", tr("All files (*.*)"));
    if(!fileName.isEmpty()) {
        ui->lineEditOutputFile->setText(fileName);
    }
}

void MainWindow::on_pushButtonRsaPublicKey_clicked()
{
    QString keyFileName = QFileDialog::getOpenFileName(this, tr("Select RSA Key"), "/home/gianmarco/Desktop", NULL);
    if (!keyFileName.isEmpty()) {
        ui->lineEditPublicKey->setText(keyFileName);
    }
}

void MainWindow::on_pushButtonRsaPrivateKey_clicked()
{
    QString keyFileName = QFileDialog::getOpenFileName(this, tr("Select RSA Key"), "/home/gianmarco/Desktop", NULL);
    if (!keyFileName.isEmpty()) {
        ui->lineEditPrivateKey->setText(keyFileName);
    }
}

//void MainWindow::handleErrors(void)
//{
//  ERR_print_errors_fp(stderr);
//  abort();
//}

void MainWindow::on_radioButtonRsaPublicKey_clicked()
{
    mRSAKeyType = ui->radioButtonRsaPublicKey->isChecked() ? RSA_PUBLIC_KEY : RSA_PRIVATE_KEY;
    updateRsaKeyMode();
}

void MainWindow::on_radioButtonRsaPrivateKey_clicked()
{
    mRSAKeyType = ui->radioButtonRsaPrivateKey->isChecked() ? RSA_PRIVATE_KEY : RSA_PUBLIC_KEY;
    updateRsaKeyMode();
}

void MainWindow::updateRsaKeyMode()
{
    bool state = mRSAKeyType == RSA_PUBLIC_KEY;
    ui->lineEditPublicKey->setEnabled(state);
    ui->pushButtonRsaPublicKey->setEnabled(state);
    ui->lineEditPrivateKey->setEnabled(!state);
    ui->pushButtonRsaPrivateKey->setEnabled(!state);
}

void MainWindow::on_pushButtonRsaEncrypt_clicked()
{
    runRsaOperation(ENCRYPT, mRSAKeyType);
}

void MainWindow::on_pushButtonRsaDecrypt_clicked()
{
    runRsaOperation(DECRYPT, mRSAKeyType);
}

void MainWindow::runRsaOperation(int operation, int key_type)
{
    QString inputFile = ui->lineEditInputFile->text();
    QString outputFile = ui->lineEditOutputFile->text();
    QString RSAPublicKeyFile = ui->lineEditPublicKey->text();
    QString RSAPrivateKeyFile = ui->lineEditPrivateKey->text();

    if (inputFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No input file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (outputFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No output file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (key_type == RSA_PUBLIC_KEY && RSAPublicKeyFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No public key file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (key_type == RSA_PRIVATE_KEY && RSAPrivateKeyFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No private key file selected!"),
                              QMessageBox::Ok);
        return;
    }

    RSA *rsa;
    int rsa_size;
    int file_size;
    int enc_file_size;
    int blocks;
    char err_string[256];
    FILE *fp;
    FILE *fp2;
    unsigned char *in_buffer;
    unsigned char *out_buffer;
    int block_size;
    int write_size;
    int extra_block = 0;
    int extra_bytes;
    int padding;

    ERR_load_CRYPTO_strings();

    fp = fopen(inputFile.toStdString().c_str(), "r");
    if (fp == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the input file. Please check."),
                              QMessageBox::Ok);
        return;
    }
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);

    if (key_type == RSA_PUBLIC_KEY) {
        rsa = createRSAWithFilename(RSAPublicKeyFile.toStdString().c_str(), 1);
    } else if (key_type == RSA_PRIVATE_KEY) {
        rsa = createRSAWithFilename(RSAPrivateKeyFile.toStdString().c_str(), 0);
    }

    if (rsa == NULL) {
        ERR_error_string(ERR_get_error(), err_string);
        QMessageBox::critical(this, tr("Key error"), QString::fromUtf8((const char*)err_string),
                              QMessageBox::Ok);
        goto end;
    }

    rsa_size = RSA_size(rsa);
    enc_file_size = (file_size % rsa_size) ?
                (file_size + rsa_size - (file_size % rsa_size)) : file_size;
    in_buffer = (unsigned char*) malloc(sizeof(unsigned char)*rsa_size);
    out_buffer = (unsigned char*) malloc(sizeof(unsigned char)*rsa_size);
    blocks = enc_file_size / rsa_size;
    if ((file_size % rsa_size) > (256-11)) {
        blocks++;
        extra_block = 1;
        extra_bytes = (file_size % rsa_size) - (256-11);
    }

    fp2 = fopen(outputFile.toStdString().c_str(), "w");

    for (int i=0; i<blocks; i++) {
        if (i == blocks-1) {
            padding = RSA_PKCS1_PADDING;
            block_size = (file_size % rsa_size) ? (file_size % rsa_size) : rsa_size;
            if (extra_block) {
                block_size = extra_bytes;
            }
        } else if (extra_block && (i == blocks-2)) {
            block_size = rsa_size - 11;
            padding = RSA_NO_PADDING;
        } else {
            padding = RSA_NO_PADDING;
            block_size = rsa_size;
        }

        memset(out_buffer, 0, rsa_size);

        fread(in_buffer, sizeof(unsigned char), block_size, fp);
        if (key_type == RSA_PUBLIC_KEY) {
            if (operation == ENCRYPT) {
                RSA_public_encrypt(block_size, in_buffer, out_buffer, rsa, padding);
            } else {
                RSA_public_decrypt(block_size, in_buffer, out_buffer, rsa, padding);
            }
        } else if (key_type == RSA_PRIVATE_KEY) {
            if (operation == ENCRYPT) {
                RSA_private_encrypt(block_size, in_buffer, out_buffer, rsa, padding);
            } else {
                RSA_private_decrypt(block_size, in_buffer, out_buffer, rsa, padding);
            }
        }

        write_size = rsa_size;
        if (operation == DECRYPT && i == blocks-1) {
            for (int j=0; j<rsa_size; j++) {
                if (out_buffer[j] == 0) {
                    write_size = j;
                    break;
                }
            }
        }
        fwrite(out_buffer, sizeof(unsigned char), write_size, fp2);
    }

    fclose(fp2);

    if (QMessageBox::information(this, tr("Operation completed"),
                             tr("The output file has been generated."),
                             QMessageBox::Ok | QMessageBox::Open) == QMessageBox::Open) {
        QProcess::execute("gedit", QStringList() << outputFile);
    }

    free(out_buffer);
    free(in_buffer);
end:
    ERR_free_strings();
    fclose(fp);

}

void MainWindow::on_pushButtonGenerateKey_clicked()
{
    int key_length = getKeyLength(getCipherFromUi());
    char error_string[256];
    char temp[3];
    QString key_string;
    unsigned char *buffer = (unsigned char*) malloc(sizeof(unsigned char)*key_length);

    if (generateRandomNumber(buffer, key_length)) {
        ERR_error_string(ERR_get_error(), error_string);
        QMessageBox::critical(this, tr("Error"), QString::fromUtf8(error_string), QMessageBox::Ok);
    } else {
        for(int i=0; i<key_length; i++) {
            // Print key in hex format
            if (buffer[i] < 0x10) {
                key_string.append("0");
            }
            sprintf(temp, "%x", buffer[i]);
            key_string.append(temp);
        }
        ui->lineEditSymmetricKey->setText(key_string);
    }

    free(buffer);
}

void MainWindow::on_pushButtonGenerateIV_clicked()
{
    int iv_length = getIvLength(getCipherFromUi());
    char error_string[256];
    char temp[3];
    QString iv_string;
    unsigned char *buffer = (unsigned char*) malloc(sizeof(unsigned char)*iv_length);

    if (generateRandomNumber(buffer, iv_length)) {
        ERR_error_string(ERR_get_error(), error_string);
        QMessageBox::critical(this, tr("Error"), QString::fromUtf8(error_string), QMessageBox::Ok);
    } else {
        for(int i=0; i<iv_length; i++) {
            // Print iv in hex format
            if (buffer[i] < 0x10) {
                iv_string.append("0");
            }
            sprintf(temp, "%x", buffer[i]);
            iv_string.append(temp);
        }
        ui->lineEditIV->setText(iv_string);
    }

    free(buffer);
}

void MainWindow::runSymmetricOperation(int operation, int cipher, int mode, unsigned char *key,
                                       unsigned char *iv)
{
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER *cpr;
    char error_buffer[256];
    FILE *ifp;
    FILE *ofp;
    int input_size;
    int output_len = 0;
    int step_len = 0;
    unsigned char *input_buffer;
    unsigned char *output_buffer;
    QString inputFile = ui->lineEditInputFile->text();
    QString outputFile = ui->lineEditOutputFile->text();
    char *input_file = (char*) malloc(inputFile.size()+1);
    char *output_file = (char*) malloc(outputFile.size()+1);
    int ret;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    cpr = getEvpCipher(cipher, mode);

    EVP_CIPHER_CTX_init(&ctx);

    if (operation == ENCRYPT) {
        ret = EVP_EncryptInit(&ctx, cpr, key, iv);
    } else {
        ret = EVP_DecryptInit(&ctx, cpr, key, iv);
    }

    if (ret == 0) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        goto end4;
    }

    strcpy(input_file, inputFile.toStdString().c_str());
    ifp = fopen(input_file, "r");
    if (ifp == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the input file. Please check."),
                              QMessageBox::Ok);
        goto end4;
    }

    strcpy(output_file, outputFile.toStdString().c_str());
    ofp = fopen(output_file, "w");
    if (ofp == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the output file. Please check."),
                              QMessageBox::Ok);
        goto end5;
    }

    fseek(ifp, 0, SEEK_END);
    input_size = ftell(ifp);
    rewind(ifp);
    input_buffer = (unsigned char*) malloc(input_size);
    output_buffer = (unsigned char*) malloc(input_size + getIvLength(cipher)); // Worst case

    fread(input_buffer, 1, input_size, ifp);

    if (operation == ENCRYPT) {
        EVP_EncryptUpdate(&ctx, output_buffer, &step_len, input_buffer, input_size);
        output_len = step_len;
        EVP_EncryptFinal(&ctx, output_buffer + output_len, &step_len);
        output_len += step_len;
    } else {
        EVP_DecryptUpdate(&ctx, output_buffer, &step_len, input_buffer, input_size);
        output_len = step_len;
        EVP_DecryptFinal(&ctx, output_buffer + output_len, &step_len);
        output_len += step_len;
    }

    fwrite(output_buffer, 1, output_len, ofp);

    fclose(ofp);

    if (QMessageBox::information(this, tr("Operation completed"),
                             tr("The output file has been generated."),
                             QMessageBox::Ok | QMessageBox::Open) == QMessageBox::Open) {
        QProcess::execute("gedit", QStringList() << outputFile);
    }

end5:
    fclose(ifp);
end4:
    EVP_CIPHER_CTX_cleanup(&ctx);
    EVP_cleanup();
    ERR_free_strings();
    free(input_file);
    free(output_file);
}

EVP_CIPHER* MainWindow::getEvpCipher(int cipher, int mode)
{
    const EVP_CIPHER *ret;

    switch (cipher) {
    case CIPHER_DES:
        switch (mode) {
        case MODE_CBC:
            ret = EVP_des_cbc();
            break;
        case MODE_ECB:
            ret = EVP_des_ecb();
            break;
        case MODE_CFB:
            ret = EVP_des_cfb64();
            break;
        case MODE_OFB:
            ret = EVP_des_ofb();
            break;
        default:
            ret = NULL;
        }
        break;
    case CIPHER_3DES2:
        switch (mode) {
        case MODE_CBC:
            ret = EVP_des_ede_cbc();
            break;
        case MODE_ECB:
            ret = EVP_des_ede_ecb();
            break;
        case MODE_CFB:
            ret = EVP_des_ede_cfb64();
            break;
        case MODE_OFB:
            ret = EVP_des_ede_ofb();
            break;
        default:
            ret = NULL;
        }
        break;
    case CIPHER_3DES3:
        switch (mode) {
        case MODE_CBC:
            ret = EVP_des_ede3_cbc();
            break;
        case MODE_ECB:
            ret = EVP_des_ede3_ecb();
            break;
        case MODE_CFB:
            ret = EVP_des_ede3_cfb64();
            break;
        case MODE_OFB:
            ret = EVP_des_ede3_ofb();
            break;
        default:
            ret = NULL;
        }
        break;
    case CIPHER_AES128:
        switch (mode) {
        case MODE_CBC:
            ret = EVP_aes_128_cbc();
            break;
        case MODE_ECB:
            ret = EVP_aes_128_ecb();
            break;
        case MODE_CFB:
            ret = EVP_aes_128_cfb128();
            break;
        case MODE_OFB:
            ret = EVP_aes_128_ofb();
            break;
        default:
            ret = NULL;
        }
        break;
    case CIPHER_AES192:
        switch (mode) {
        case MODE_CBC:
            ret = EVP_aes_192_cbc();
            break;
        case MODE_ECB:
            ret = EVP_aes_192_ecb();
            break;
        case MODE_CFB:
            ret = EVP_aes_192_cfb128();
            break;
        case MODE_OFB:
            ret = EVP_aes_192_ofb();
            break;
        default:
            ret = NULL;
        }
        break;
    case CIPHER_AES256:
        switch (mode) {
        case MODE_CBC:
            ret = EVP_aes_256_cbc();
            break;
        case MODE_ECB:
            ret = EVP_aes_256_ecb();
            break;
        case MODE_CFB:
            ret = EVP_aes_256_cfb128();
            break;
        case MODE_OFB:
            ret = EVP_aes_256_ofb();
            break;
        default:
            ret = NULL;
        }
        break;
    default:
        ret = NULL;
    }

    return (EVP_CIPHER*)ret;
}

void MainWindow::on_pushButtonSymmetricEncrypt_clicked()
{
    ui->pushButtonSymmetricEncrypt->setEnabled(false);
    ui->pushButtonSymmetricDecrypt->setEnabled(false);
    prepareSymmetricOperation(ENCRYPT);
    ui->pushButtonSymmetricEncrypt->setEnabled(true);
    ui->pushButtonSymmetricDecrypt->setEnabled(true);
}

void MainWindow::on_pushButtonSymmetricDecrypt_clicked()
{
    ui->pushButtonSymmetricDecrypt->setEnabled(false);
    ui->pushButtonSymmetricEncrypt->setEnabled(false);
    prepareSymmetricOperation(DECRYPT);
    ui->pushButtonSymmetricDecrypt->setEnabled(true);
    ui->pushButtonSymmetricEncrypt->setEnabled(true);
}

void MainWindow::prepareSymmetricOperation(int operation)
{
    QString inputFile = ui->lineEditInputFile->text();
    QString outputFile = ui->lineEditOutputFile->text();
    if (inputFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No input file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (outputFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No output file selected!"),
                              QMessageBox::Ok);
        return;
    }

    int cipher = getCipherFromUi();
    int mode = getModeFromUi();
    int key_length = getKeyLength(cipher);
    int iv_length = getIvLength(cipher);

    QString key_string = ui->lineEditSymmetricKey->text();
    if (key_string.length() != 2*key_length) {
        QMessageBox::critical(this, tr("Error"), tr("The inserted key length is not\n"
                                                    "compatible with the selected cipher."),
                              QMessageBox::Ok);
        return;
    }

    QString iv_string = ui->lineEditIV->text();
    if (mode != MODE_ECB && iv_string.length() != 2*iv_length) {
        QMessageBox::critical(this, tr("Error"), tr("The inserted IV length is not\n"
                                                    "compatible with the selected cipher."),
                              QMessageBox::Ok);
        return;
    }

    unsigned char *key = (unsigned char *) malloc(sizeof(unsigned char)*key_length);
    unsigned char *iv = (unsigned char *) malloc(sizeof(unsigned char)*iv_length);
    char temp[3];

    for(int i=0; i<key_length; i++) {
        sprintf(temp, "%c%c", key_string.toStdString().c_str()[i*2],
                key_string.toStdString().c_str()[i*2+1]);
        key[i] = strtoul(temp, NULL, 16);
    }
    for(int i=0; i<iv_length; i++) {
        sprintf(temp, "%c%c", iv_string.toStdString().c_str()[i*2],
                iv_string.toStdString().c_str()[i*2+1]);
        iv[i] = strtoul(temp, NULL, 16);
    }

    runSymmetricOperation(operation, cipher, mode, key, iv);

    free(iv);
    free(key);
}

int MainWindow::getCipherFromUi()
{
    QString cipher = ui->comboBoxCipher->currentText();

    if (cipher.compare("DES") == 0) {
        return CIPHER_DES;
    } else if (cipher.compare("3DES2") == 0) {
        return CIPHER_3DES2;
    } else if (cipher.compare("3DES3") == 0) {
        return CIPHER_3DES3;
    } else if (cipher.compare("AES128") == 0) {
        return CIPHER_AES128;
    } else if (cipher.compare("AES192") == 0) {
        return CIPHER_AES192;
    } else if (cipher.compare("AES256") == 0) {
        return CIPHER_AES256;
    } else {
        return 0;
    }
}

int MainWindow::getModeFromUi()
{
    QString mode = ui->comboBoxMode->currentText();

    if (mode.compare("ECB") == 0) {
        return MODE_ECB;
    } else if (mode.compare("CBC") == 0) {
        return MODE_CBC;
    } else if (mode.compare("CFB") == 0) {
        return MODE_CFB;
    } else if (mode.compare("OFB") == 0) {
        return MODE_OFB;
    } else {
        return 0;
    }
}

int MainWindow::getKeyLength(int cipher)
{
    if (cipher == CIPHER_DES ) {
        return 56/8;
    } else {
        switch (cipher) {
        case CIPHER_AES128:
            return 128/8;
        case CIPHER_AES192:
            return 192/8;
        case CIPHER_AES256:
            return 256/8;
        default:
            return 0;
        }
    }
}

int MainWindow::getIvLength(int cipher)
{
    if (cipher == CIPHER_AES128 || cipher == CIPHER_AES192 || cipher == CIPHER_AES256) {
        return 128/8;
    } else {
        return 64/8;
    }
}

void MainWindow::on_comboBoxMode_currentIndexChanged(int index)
{
    bool state;
    if (ui->comboBoxMode->currentText().compare("ECB") == 0) {
        state = false;
        ui->lineEditIV->clear();
    } else {
        state = true;
    }
    ui->lineEditIV->setEnabled(state);
    ui->pushButtonGenerateIV->setEnabled(state);
}

int MainWindow::getCipherFromUi2()
{
    QString cipher = ui->comboBoxCipher_2->currentText();

    if (cipher.compare("DES") == 0) {
        return CIPHER_DES;
    } else if (cipher.compare("3DES2") == 0) {
        return CIPHER_3DES2;
    } else if (cipher.compare("3DES3") == 0) {
        return CIPHER_3DES3;
    } else if (cipher.compare("AES128") == 0) {
        return CIPHER_AES128;
    } else if (cipher.compare("AES192") == 0) {
        return CIPHER_AES192;
    } else if (cipher.compare("AES256") == 0) {
        return CIPHER_AES256;
    } else {
        return 0;
    }
}

int MainWindow::getModeFromUi2()
{
    QString mode = ui->comboBoxMode_2->currentText();

    if (mode.compare("ECB") == 0) {
        return MODE_ECB;
    } else if (mode.compare("CBC") == 0) {
        return MODE_CBC;
    } else if (mode.compare("CFB") == 0) {
        return MODE_CFB;
    } else if (mode.compare("OFB") == 0) {
        return MODE_OFB;
    } else {
        return 0;
    }
}

void MainWindow::on_pushButtonGenerateIV_2_clicked()
{
    int iv_length = getIvLength(getCipherFromUi2());
    char error_string[256];
    char temp[3];
    QString iv_string;
    unsigned char *buffer = (unsigned char*) malloc(sizeof(unsigned char)*iv_length);

    if (generateRandomNumber(buffer, iv_length)) {
        ERR_error_string(ERR_get_error(), error_string);
        QMessageBox::critical(this, tr("Error"), QString::fromUtf8(error_string), QMessageBox::Ok);
    } else {
        for(int i=0; i<iv_length; i++) {
            // Print iv in hex format
            if (buffer[i] < 0x10) {
                iv_string.append("0");
            }
            sprintf(temp, "%x", buffer[i]);
            iv_string.append(temp);
        }
        ui->lineEditIV_2->setText(iv_string);
    }

    free(buffer);
}

void MainWindow::on_pushButtonRsaPublicKey_2_clicked()
{
    QString keyFileName = QFileDialog::getOpenFileName(this, tr("Select RSA Key"), "/home/gianmarco/Desktop", NULL);
    if (!keyFileName.isEmpty()) {
        ui->lineEditPublicKey_2->setText(keyFileName);
    }
}

int MainWindow::envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
                              unsigned char **encrypted_key, int *encrypted_key_len,
                              unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int ciphertext_len;
    int len;
    char error_buffer[256];

    int cipher = getCipherFromUi2();
    int mode = getModeFromUi2();

    ERR_load_crypto_strings();

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        ERR_free_strings();
        return 0;
    }

    /* Initialise the envelope seal operation. This operation generates
         * a key for the provided cipher, and then encrypts that key a number
         * of times (one for each public key provided in the pub_key array). In
         * this example the array size is just one. This operation also
         * generates an IV and places it in iv. */
    if(1 != EVP_SealInit(ctx, getEvpCipher(cipher, mode), encrypted_key,
                         encrypted_key_len, iv, pub_key, 1)) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        ERR_free_strings();
        return 0;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_SealUpdate can be called multiple times if necessary
         */
    if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        ERR_free_strings();
        return 0;
    }

    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
         * this stage.
         */
    if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        ERR_free_strings();
        return 0;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    ERR_free_strings();

    return ciphertext_len;
}


void MainWindow::on_pushButtonSymmetricEncrypt_2_clicked()
{
    QString inputFile = ui->lineEditInputFile->text();
    QString outputFile = ui->lineEditOutputFile->text();
    QString publicKeyFile = ui->lineEditPublicKey_2->text();

    if (inputFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No input file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (outputFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No output file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (publicKeyFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No public key file selected!"),
                              QMessageBox::Ok);
        return;
    }

    EVP_PKEY *pKey;
    FILE *keyFP;
    FILE *ifp;
    FILE *ofp;
    char *input_file;
    char *output_file;
    char *key_file;
    char *passphrase;
    unsigned char *input_buffer;
    unsigned char *output_buffer;
    int input_size;
    unsigned char *encrypted_key;
    int encrypted_key_length;
    int output_length;

    int cipher = getCipherFromUi2();
    int mode = getModeFromUi2();

    // Input file
    input_file = (char*) malloc(inputFile.size()+1);
    strcpy(input_file, inputFile.toStdString().c_str());
    ifp = fopen(input_file, "r");
    free(input_file);
    if (ifp == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the input file. Please check."),
                              QMessageBox::Ok);
        return;
    }

    // Output file
    output_file = (char*) malloc(outputFile.size()+1);
    strcpy(output_file, outputFile.toStdString().c_str());
    ofp = fopen(output_file, "wb");
    free(output_file);
    if (ofp == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the output file. Please check."),
                              QMessageBox::Ok);
        fclose(ifp);
        return;
    }

    // Public Key file
    key_file = (char*) malloc(publicKeyFile.size()+1);
    strcpy(key_file, publicKeyFile.toStdString().c_str());
    keyFP = fopen(key_file, "r");
    free(key_file);
    if (keyFP == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the key file. Please check."),
                              QMessageBox::Ok);
        fclose(ifp);
        fclose(ofp);
        return;
    }

    // Input file size
    fseek(ifp, 0, SEEK_END);
    input_size = ftell(ifp);
    rewind(ifp);
    input_buffer = (unsigned char*) malloc(input_size);
    output_buffer = (unsigned char*) malloc(input_size + getIvLength(cipher)); // Worst case
    fread(input_buffer, 1, input_size, ifp);

    // Init Vector
    //int iv_length = getIvLength(cipher);
    int iv_length = EVP_CIPHER_iv_length(getEvpCipher(cipher, mode));
//    QString iv_string = ui->lineEditIV_2->text();
//    if (mode != MODE_ECB && iv_string.length() != 2*iv_length) {
//        QMessageBox::critical(this, tr("Error"), tr("The inserted IV length is not\n"
//                                                    "compatible with the selected cipher."),
//                              QMessageBox::Ok);
//        fclose(ifp);
//        fclose(ofp);
//        free(input_buffer);
//        free(output_buffer);
//        return;
//    }
    unsigned char *iv = (unsigned char *) malloc(iv_length);
//    char temp[3];
//    for(int i=0; i<iv_length; i++) {
//        sprintf(temp, "%c%c", iv_string.toStdString().c_str()[i*2],
//                iv_string.toStdString().c_str()[i*2+1]);
//        iv[i] = strtoul(temp, NULL, 16);
//    }

    // OpenSSL init
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    // Passphrase
    passphrase = (char*) malloc(ui->lineEditPassphrase->text().size()+1);
    strcpy(passphrase, ui->lineEditPassphrase->text().toStdString().c_str());
    pKey = PEM_read_PUBKEY(keyFP, NULL, &pem_pass_cb, passphrase);
    free(passphrase);
    if (pKey == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the key file. Please check."),
                              QMessageBox::Ok);
        fclose(ifp);
        fclose(ofp);
        free(input_buffer);
        free(output_buffer);
        free(iv);
        return;
    }

    encrypted_key = (unsigned char*) malloc(EVP_PKEY_size(pKey));
    output_length = envelope_seal(&pKey, input_buffer, input_size, &encrypted_key, &encrypted_key_length, iv, output_buffer);

    if (output_length != 0) {
        // Print generated IV
        QString iv_string;
        char temp[3];
        for(int i=0; i<iv_length; i++) {
            // Print iv in hex format
            if (iv[i] < 0x10) {
                iv_string.append("0");
            }
            sprintf(temp, "%x", iv[i]);
            iv_string.append(temp);
        }
        ui->lineEditIV_2->setText(iv_string);

        // Write output
        fwrite(output_buffer, 1, output_length, ofp);
        fclose(ofp);

        // Write encrypted key
        char *enc_key_file = (char*) malloc(ui->lineEditOutputKey->text().size()+1);
        strcpy(enc_key_file, ui->lineEditOutputKey->text().toStdString().c_str());
        FILE *enc_key_fp = fopen(enc_key_file, "wb");
        fwrite(encrypted_key, 1, encrypted_key_length, enc_key_fp);
        fclose(enc_key_fp);

        // Write encrypted key length
        char *enc_key_len_file = (char*) malloc(strlen(enc_key_file)+3);
        //int enc_key_len_size = (int) log10((double)encrypted_key_length) + 1;
        //char *enc_key_len_buf = (char*) malloc(enc_key_len_size);
        //sprintf(enc_key_len_buf, "%d", encrypted_key_length);
        strcpy(enc_key_len_file, enc_key_file);
        strcat(enc_key_len_file, "len");
        //FILE *enc_key_len_fp = fopen(enc_key_len_file, "w");
        FILE *enc_key_len_fp = fopen(enc_key_len_file, "wb");
        //fwrite(enc_key_len_buf, 1, enc_key_len_size, enc_key_len_fp);
        fwrite(&encrypted_key_length, sizeof(encrypted_key_length), 1, enc_key_len_fp);
        fclose(enc_key_len_fp);
        //free(enc_key_len_buf);
        free(enc_key_len_file);
        free(enc_key_file);

        if (QMessageBox::information(this, tr("Operation completed"),
                                     tr("The output file has been generated."),
                                     QMessageBox::Ok | QMessageBox::Open) == QMessageBox::Open) {
            QProcess::execute("gedit", QStringList() << outputFile);
        }
    } else {
        fclose(ofp);
    }

    free(input_buffer);
    free(output_buffer);
    free(iv);
}

void MainWindow::on_pushButtonSelectKey_clicked()
{
    QString keyFileName = QFileDialog::getOpenFileName(this, tr("Select Encrypted Key"), "/home/gianmarco/Desktop", NULL);
    if (!keyFileName.isEmpty()) {
        ui->lineEditInputKey->setText(keyFileName);
    }
}

void MainWindow::on_pushButtonSaveKey_clicked()
{
    QString keyFileName = QFileDialog::getSaveFileName(this, tr("Select Encrypted Key"), "/home/gianmarco/Desktop", NULL);
    if (!keyFileName.isEmpty()) {
        ui->lineEditOutputKey->setText(keyFileName);
    }
}

void MainWindow::on_pushButtonSymmetricDecrypt_2_clicked()
{
    QString inputFile = ui->lineEditInputFile->text();
    QString outputFile = ui->lineEditOutputFile->text();
    QString privateKeyFile = ui->lineEditPublicKey_2->text();

    if (inputFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No input file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (outputFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No output file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (privateKeyFile.isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No private key file selected!"),
                              QMessageBox::Ok);
        return;
    }
    if (ui->lineEditInputKey->text().isEmpty()) {
        QMessageBox::critical(this, tr("Error!"), tr("No encrypted key file selected!"),
                              QMessageBox::Ok);
        return;
    }

    EVP_PKEY *pKey;
    FILE *keyFP;
    FILE *ifp;
    FILE *ofp;
    char *input_file;
    char *output_file;
    char *key_file;
    char *passphrase;
    unsigned char *input_buffer;
    unsigned char *output_buffer;
    int input_size;
    unsigned char *encrypted_key;
    int encrypted_key_length;
    int output_length;

    int cipher = getCipherFromUi2();
    int mode = getModeFromUi2();

    // Input file
    input_file = (char*) malloc(inputFile.size()+1);
    strcpy(input_file, inputFile.toStdString().c_str());
    ifp = fopen(input_file, "rb");
    free(input_file);
    if (ifp == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the input file. Please check."),
                              QMessageBox::Ok);
        return;
    }

    // Output file
    output_file = (char*) malloc(outputFile.size()+1);
    strcpy(output_file, outputFile.toStdString().c_str());
    ofp = fopen(output_file, "w");
    free(output_file);
    if (ofp == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the output file. Please check."),
                              QMessageBox::Ok);
        fclose(ifp);
        return;
    }

    // Private Key file
    key_file = (char*) malloc(privateKeyFile.size()+1);
    strcpy(key_file, privateKeyFile.toStdString().c_str());
    keyFP = fopen(key_file, "r");
    free(key_file);
    if (keyFP == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the key file. Please check."),
                              QMessageBox::Ok);
        fclose(ifp);
        fclose(ofp);
        return;
    }

    // Input file size
    fseek(ifp, 0, SEEK_END);
    input_size = ftell(ifp);
    rewind(ifp);
    input_buffer = (unsigned char*) malloc(input_size);
    output_buffer = (unsigned char*) malloc(input_size + getIvLength(cipher)); // Worst case
    fread(input_buffer, 1, input_size, ifp);

    // Init Vector
    int iv_length = getIvLength(cipher);
    QString iv_string = ui->lineEditIV_2->text();
    if (mode != MODE_ECB && iv_string.length() != 2*iv_length) {
        QMessageBox::critical(this, tr("Error"), tr("The inserted IV length is not\n"
                                                    "compatible with the selected cipher."),
                              QMessageBox::Ok);
        fclose(ifp);
        fclose(ofp);
        free(input_buffer);
        free(output_buffer);
        return;
    }
    unsigned char *iv = (unsigned char *) malloc(sizeof(unsigned char)*iv_length);
    char temp[3];
    for(int i=0; i<iv_length; i++) {
        sprintf(temp, "%c%c", iv_string.toStdString().c_str()[i*2],
                iv_string.toStdString().c_str()[i*2+1]);
        iv[i] = strtoul(temp, NULL, 16);
    }

    // Read encrypted key
    char *enc_key_file = (char*) malloc(ui->lineEditInputKey->text().size()+1);
    strcpy(enc_key_file, ui->lineEditInputKey->text().toStdString().c_str());
    FILE *enc_key_fp = fopen(enc_key_file, "rb");
    fseek(enc_key_fp, 0, SEEK_END);
    int enc_key_file_len = ftell(enc_key_fp);
    rewind(enc_key_fp);
    encrypted_key = (unsigned char*) malloc(enc_key_file_len);
    fread(encrypted_key, 1, enc_key_file_len, enc_key_fp);
    fclose(enc_key_fp);

    // Read encrypted key length
    char *enc_key_len_file = (char*) malloc(strlen(enc_key_file)+3);
    strcpy(enc_key_len_file, enc_key_file);
    strcat(enc_key_len_file, "len");
    FILE *enc_key_len_fp = fopen(enc_key_len_file, "rb");
    if (enc_key_len_fp != NULL) {
        fseek(enc_key_len_fp, 0, SEEK_END);
        int enc_key_len_file_len = ftell(enc_key_len_fp);
        rewind(enc_key_len_fp);
        //char *enc_key_len_buf = (char*) malloc(enc_key_len_file_len);
        //fread(enc_key_len_buf, 1, enc_key_len_file_len, enc_key_len_fp);
        fread(&encrypted_key_length, sizeof(encrypted_key_length),
              enc_key_len_file_len/sizeof(encrypted_key_length), enc_key_len_fp);
        //encrypted_key_length = strtoul(enc_key_len_buf, &enc_key_len_buf + enc_key_len_file_len, 10);
        fclose(enc_key_len_fp);
        //free(enc_key_len_buf);
    } else {
        encrypted_key_length = 256;
    }
    free(enc_key_len_file);
    free(enc_key_file);

    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    passphrase = (char*) malloc(ui->lineEditPassphrase->text().size()+1);
    strcpy(passphrase, ui->lineEditPassphrase->text().toStdString().c_str());
    pKey = PEM_read_PrivateKey(keyFP, NULL, &pem_pass_cb, passphrase);
    free(passphrase);
    if (pKey == NULL) {
        QMessageBox::critical(this, tr("File error"), tr("An error occurred while opening\n"
                                                         "the key file. Please check."),
                              QMessageBox::Ok);
        fclose(ifp);
        fclose(ofp);
        free(iv);
        free(input_buffer);
        free(output_buffer);
        free(encrypted_key);
        return;
    }

    output_length = envelope_open(pKey, input_buffer, input_size, encrypted_key,
                                  encrypted_key_length, iv, output_buffer);

    if (output_length != 0) {
        // Write output
        fwrite(output_buffer, 1, output_length, ofp);
        fclose(ofp);

        if (QMessageBox::information(this, tr("Operation completed"),
                                     tr("The output file has been generated."),
                                     QMessageBox::Ok | QMessageBox::Open) == QMessageBox::Open) {
            QProcess::execute("gedit", QStringList() << outputFile);
        }
    } else {
        fclose(ofp);
    }

    free(input_buffer);
    free(output_buffer);
    free(encrypted_key);
    if(getIvLength(cipher)) free(iv);
}

int MainWindow::envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
                              unsigned char *encrypted_key, int encrypted_key_len,
                              unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    char error_buffer[256];

    int cipher = getCipherFromUi2();
    int mode = getModeFromUi2();

    ERR_load_crypto_strings();

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        ERR_free_strings();
        return 0;
    }

    /* Initialise the decryption operation. The asymmetric private key is
         * provided and priv_key, whilst the encrypted session key is held in
         * encrypted_key */
    if(1 != EVP_OpenInit(ctx, getEvpCipher(cipher, mode), encrypted_key,
                         encrypted_key_len, iv, priv_key)) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        ERR_free_strings();
        return 0;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_OpenUpdate can be called multiple times if necessary
         */
    if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        ERR_free_strings();
        return 0;
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
         * this stage.
         */
    if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) {
        ERR_error_string(ERR_get_error(), error_buffer);
        QMessageBox::critical(this, tr("OpenSSL error"),
                              QString::fromUtf8((const char*)error_buffer), QMessageBox::Ok);
        ERR_free_strings();
        return 0;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    ERR_free_strings();

    return plaintext_len;
}

void MainWindow::on_comboBoxMode_2_currentIndexChanged(int index)
{
    bool state;
    if (ui->comboBoxMode_2->currentText().compare("ECB") == 0) {
        state = false;
        ui->lineEditIV_2->clear();
    } else {
        state = true;
    }
    ui->lineEditIV_2->setEnabled(state);
    ui->pushButtonGenerateIV_2->setEnabled(state);
}
