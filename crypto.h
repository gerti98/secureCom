#ifndef FUNCTIONS_CRYPTO_INCLUDED
#define FUNCTIONS_CRYPTO_INCLUDED

#include <openssl/evp.h>

using uchar=unsigned char;
using namespace std;

int sym_encrypt(const EVP_CIPHER *cypher, uchar *plaintext, int plaintext_len, uchar *key, uchar **iv,  uchar **ciphertext);
int sym_decrypt(const EVP_CIPHER *cypher, uchar **plaintext, int ciphertext_len, uchar *key, uchar *iv, uchar *ciphertext);
int aes_128_cbc_encrypt(uchar *plaintext, int plaintext_len, uchar *key, uchar **iv, uchar **ciphertext);
int aes_128_cbc_decrypt(uchar **plaintext, int ciphertext_len, uchar *key, uchar *iv, uchar *ciphertext);

#endif