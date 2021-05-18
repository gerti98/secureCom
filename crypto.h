#ifndef FUNCTIONS_CRYPTO_INCLUDED
#define FUNCTIONS_CRYPTO_INCLUDED

#include <openssl/evp.h>

using uchar=unsigned char;
using namespace std;

/**
 * @brief generic simmetric encryptioon function 
 * 
 * @param cypher input 
 * @param plaintext input 
 * @param plaintext_len input
 * @param key input
 * @param iv output
 * @param ciphertext output
 * @return ciphertext lenght, 0 on error
 */
int sym_encrypt(const EVP_CIPHER *cypher, uchar *plaintext, int plaintext_len, uchar *key, uchar **iv,  uchar **ciphertext);

/**
 * @brief generic simmetric decryptioon function 
 * 
 * @param cypher input 
 * @param plaintext output
 * @param ciphertext_len input
 * @param key input
 * @param iv input
 * @param ciphertext input
 * @return plaintext lenght, 0 on error
 */
int sym_decrypt(const EVP_CIPHER *cypher, uchar **plaintext, int ciphertext_len, uchar *key, uchar *iv, uchar *ciphertext);

int aes_128_cbc_encrypt(uchar *plaintext, int plaintext_len, uchar *key, uchar **iv, uchar **ciphertext);
int aes_128_cbc_decrypt(uchar **plaintext, int ciphertext_len, uchar *key, uchar *iv, uchar *ciphertext);

/**
 * @brief aes gcm mac decrypt
 * 
 * @param ciphertext input
 * @param ciphertext_len input
 * @param aad input
 * @param aad_len input
 * @param key input
 * @param tag input
 * @param iv input
 * @param plaintext output
 * @return plaintext lenght, 0 on error
 */
int aes_gcm_decrypt(uchar *ciphertext, uint ciphertext_len, uchar* aad, uint aad_len, uchar *key, uchar* tag,
                    uchar *iv,  uchar **plaintext);


/**
 * @brief aes gcm mac encrypt
 * 
 * @param plaintext input
 * @param plaintext_len input
 * @param aad input
 * @param aad_len input
 * @param key input
 * @param tag ouput
 * @param iv output
 * @param ciphertext output
 * @return ciphertext lenght, 0 on error
 */
int aes_gcm_encrypt( uchar *plaintext, int plaintext_len, uchar* aad, uint aad_len, uchar *key, uchar** tag,
                    uchar **iv,  uchar **ciphertext);
                    
/**
 * @brief digest computation
 * 
 * @param cypher input
 * @param plaintext input
 * @param plaintext_len input
 * @param ciphertext output
 * @return digest length, 0 on error
 */
uint digest(const EVP_MD* cypher, uchar* plaintext, uint plaintext_len, uchar** ciphertext);

uint sha_256_digest(uchar* plaintext, uint plaintext_len, uchar** chipertext);

/**
 * @brief serialize a certificate
 * 
 * @param cert_file input
 * @param certificate output
 * @return lenght of the buffer, 0 on error(s)
 */
int serialize_certificate(FILE* cert_file, uchar** certificate);

/**
 * @brief verify a signature on a docuemnt using the public key of the signer (passed in a buffer)
 * 
 * @param signature input
 * @param sign_lenght input
 * @param document input
 * @param doc_lenght input
 * @param pubkey input
 * @param key_lenght input
 * @return 1 if succesfully, 0 otherwise
 */
int verify_sign_pubkey(uchar* signature, uint sign_lenght, uchar* document, uint doc_lenght, uchar* pubkey, uint key_lenght);

/**
 * @brief verify a signature on a docuemnt using the public key of the signer (passed as a file)
 * 
 * @param signature input
 * @param sign_lenght input
 * @param document input
 * @param doc_lenght input
 * @param pubkey input
 * @return int 
 */
int verify_sign_pubkey(uchar* signature, uint sign_lenght, uchar* document, uint doc_lenght, 
    FILE*pubkey);
    
/**
 * @brief verify a signature on a docuemnt using a certificate, signed by a certification authority
 * 
 * @param certificate input certificate of the signer
 * @param cert_lenght input lenght of the certificate of the signer
 * @param CAcertificate input certificate of the CA
 * @param CACtrl input
 * @param signature input
 * @param sign_lenght input
 * @param document input
 * @param doc_lenght input
 * @return 1 if succesfully, 0 otherwise
 */
int verify_sign_cert(const uchar* certificate, const uint cert_lenght,  FILE* const CAcertificate,  
    FILE* const CAcrl, uchar* signature, uint sign_lenght, uchar* document, uint doc_lenght );

/**
 * @brief sign a document with a priv_key
 * 
 * @param document innput
 * @param doc_lenght input
 * @param priv_key input private key file
 * @param signature output 
 * @param sign_lenght output
 * @return 1 if successful, 0 otherwise 
 */
int sign_document( const uchar* document, uint doc_lenght, FILE* const priv_key,uchar** signature, uint* sign_lenght);
#endif