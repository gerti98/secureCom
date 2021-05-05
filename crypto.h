#ifndef FUNCTIONS_CRYPTO_INCLUDED
#define FUNCTIONS_CRYPTO_INCLUDED

#include <openssl/evp.h>

using uchar=unsigned char;
using namespace std;

int sym_encrypt(const EVP_CIPHER *cypher, uchar *plaintext, int plaintext_len, uchar *key, uchar **iv,  uchar **ciphertext);
int sym_decrypt(const EVP_CIPHER *cypher, uchar **plaintext, int ciphertext_len, uchar *key, uchar *iv, uchar *ciphertext);
int aes_128_cbc_encrypt(uchar *plaintext, int plaintext_len, uchar *key, uchar **iv, uchar **ciphertext);
int aes_128_cbc_decrypt(uchar **plaintext, int ciphertext_len, uchar *key, uchar *iv, uchar *ciphertext);
int aes_gcm_decrypt(uchar *ciphertext, uint ciphertext_len, uchar* aad, uint aad_len, uchar *key, uchar* tag,
                    uchar *iv,  uchar **plaintext);
int aes_gcm_encrypt( uchar *plaintext, int plaintext_len, uchar* aad, uint aad_len, uchar *key, uchar** tag,
                    uchar **iv,  uchar **ciphertext);
uint digest(const EVP_MD* cypher, uchar* plaintext, uint plaintext_len, uchar** ciphertext);
uint sha_256_digest(uchar* plaintext, uint plaintext_len, uchar** chipertext);

#endif