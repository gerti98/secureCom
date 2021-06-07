#ifndef FUNCTIONS_CRYPTO_INCLUDED
#define FUNCTIONS_CRYPTO_INCLUDED

#include <openssl/evp.h>

using uchar=unsigned char;
using namespace std;

/**
 * @brief authenticated encryption decrypt
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
int auth_enc_decrypt(uchar *ciphertext, uint ciphertext_len, uchar* aad, uint aad_len, uchar *key, uchar* tag,
                    uchar *iv,  uchar **plaintext);


/**
 * @brief authenticated encryption encrypt
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
int auth_enc_encrypt( uchar *plaintext, int plaintext_len, uchar* aad, uint aad_len, uchar *key, uchar** tag,
                    uchar **iv,  uchar **ciphertext);

/**
 * @brief compare 2 digests (wrap the crypto memcompare)
 * 
 * @param digest1 
 * @param digest2 
 * @param len lenght of digests
 * @return  0 if equals, 1 if differents
 */
uint digest_compare(const uchar* digest1, const uchar* digest2, const uint len);

/**
 * @brief compute a digest with the default cypher
 * 
 * @param plaintext input
 * @param plaintext_len input
 * @param chipertext output
 * @return digest lenght, 0 on error(s) 
 */
uint default_digest(uchar* plaintext, uint plaintext_len, uchar** chipertext);

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
 * @brief verify a signature on a docuemnt using the public key of the signer (passed as a PEM file)
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
 * @param CAcertificate input certificate of the CA (PEM)
 * @param CACtrl input (PEM)
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
 * @param password password for private_key file, if NULL and needed it will be asked by terminal input
 * @param signature output 
 * @param sign_lenght output
 * @return 1 if successful, 0 otherwise 
 */
int sign_document( const uchar* document, uint doc_lenght, FILE* const priv_key,char* const password,uchar** signature, uint* sign_lenght);

/**
 * @brief sign a document with a priv_key
 * 
 * @param document innput
 * @param doc_lenght input
 * @param priv_key 
 * @param signature output 
 * @param sign_lenght output
 * @return 1 if successful, 0 otherwise 
 */
int sign_document( const uchar* document, uint doc_lenght, void* priv_key,uchar** signature, uint* sign_lenght);
/**
 * @brief generate a random sequence 
 * 
 * @param lenght number of random bytes
 * @param nuance output buffer (ha to be preallocated)
 * @return 1 on succes, 0 otherwise
 */
int random_generate(const uint lenght, uchar* nuance);

/**
 * @brief generate a pair of DH ephimeral key for key establishemnt
 * 
 * @param privkey output (NO SERIALIZED)
 * @param pubkey output (serialized)
 * @param pubkey_len 
 * @return 1 on succes, 0 otherwise
 */
int eph_key_generate(void** privkey, uchar** pubkey, uint* pubkey_len );

/**
 * @brief derive the shared seceret from a pair fo DH keys
 * 
 * @param privkey input (NO SERIALIZED)
 * @param peer_key input (serialized)
 * @param peer_key_len input
 * @param secret output shred secret
 * @return shared secret lenght, 0 on error(s) 
 */
uint derive_secret(void* privkey, uchar* peer_key, uint peer_key_len , uchar** secret );

/**
 * @brief dellocate an UNSERIALIZED private key in a secure way
 * 
 * @param key pointer to the key to deallocate
 */
void safe_free_privkey(void* key);

/**
 * @brief dellocate a buffer (containing a SERIALIZED key for exaple) in a secure way
 * 
 * @param buffer the buffer to deallocate 
 * @param buffer_len lenght of the buffer
 */
void safe_free(uchar* buffer, uint buffer_len );

/**
 * @brief read a private key from a file
 * 
 * @param privk_file file containing the private key
 * @param password password for private_key file, if NULL and needed it will be asked by terminal input
 * @return pointer to the UNSERIALIZED private key, musat be freed by safe_free_privkey()
 */
void* read_privkey(FILE* privk_file, char* const password);

/**
 * @brief read a public key from a file
 * 
 * @param pubk_file file containing the public key
 * @return size of serialized pubkey, 0 in case of errors
 */
int serialize_pubkey_from_file(FILE* pubk_file, uchar** pubkey_buf);
#endif