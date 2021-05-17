#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>
#include "util.h"
#include "constant.h"
#include <openssl/err.h> // for error descriptions

using uchar=unsigned char;
using namespace std;


int sym_encrypt(const EVP_CIPHER *cypher, uchar *plaintext, int plaintext_len, uchar *key, 
    uchar **iv,  uchar **ciphertext){
    
    if(plaintext_len>BUFFER_MAX){
        perror("Error: buffer too big\n");
        return 0;
    }

    if(cypher==nullptr) { 
        perror("Error: unallocated cypher\n");
        return 0;
    }
  
    int block_len = EVP_CIPHER_block_size(cypher);
    int iv_len = EVP_CIPHER_iv_length(cypher);
    if(plaintext_len > INT_MAX -block_len) { 
        perror("Error: integer overflow (meggase too big?)\n");
        return 0;
    }

    // allocate buffers
    *ciphertext = (uchar*) malloc(plaintext_len+block_len);
    if(ciphertext==nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }
    *iv = (uchar*) malloc(iv_len);
    if(iv == nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }

    // generate random IV
    RAND_poll();
    if(1 != RAND_bytes(*iv, iv_len)) { 
        perror("Error: RAND_bytes failed\n");
        return 0;
    }

    /* Create and initialize the context */
    int len;
    int ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == nullptr)    { 
        perror("Error: unallocated context\n");
        return 0;
    }

    // Encrypt init
    if(1 != EVP_EncryptInit(ctx,cypher, key, *iv)) { 
       perror("Error: encryption init failed\n");
        return 0;
    }

    // Encrypt Update: one call is enough 
    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) { 
        perror("Error: encryption update failed\n");
        return 0;
    }
    ciphertext_len = len;

    //Encrypt Final. Finalize the encryption and adds the padding
    if(1 != EVP_EncryptFinal(ctx, *ciphertext + len, &len)) { 
        perror("Error: encryption final failed\n");
        return 0;
    }
    ciphertext_len += len;

    // deallocate contxt
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int sym_decrypt(const EVP_CIPHER *cypher, uchar **plaintext, int ciphertext_len, uchar *key, 
    uchar *iv, uchar *ciphertext){

    if(cypher==nullptr) { 
        perror("Error: unallocated cypher\n");
        return 0;
    }
  
    int block_len = EVP_CIPHER_block_size(cypher);
    int iv_len = EVP_CIPHER_iv_length(cypher);

    if(iv == nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }
    
    // allocate buffers
    *plaintext = (uchar*) malloc(ciphertext_len);
    if(*plaintext==nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }
    EVP_CIPHER_CTX *ctx;
    int len;
    int plainlen;
    int res;

    /* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == nullptr)    { 
        perror("Error: unallocated context\n");
        return 0;
    }

    /* Decryption (initialization + single update + finalization */
    if(1 != EVP_DecryptInit(ctx, cypher, key, iv)){ 
        perror("Error: decrypt init failed\n");
        return 0;
    }
    if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)){ 
        perror("Error: decrypt update failed\n");
        return 0;
    }
    plainlen=len;
    if(1 != EVP_DecryptFinal(ctx, *plaintext + len, &len)){ 
        perror("Error: decrypt update failed\n");
        return 0;
    }
    plainlen += len;

    /* Context deallocation */
    EVP_CIPHER_CTX_free(ctx);

    return plainlen;
}

// aes_128_cbc wrappers
int aes_128_cbc_encrypt(uchar *plaintext, int plaintext_len, uchar *key, uchar **iv, uchar **ciphertext)
{
    return sym_encrypt(EVP_aes_128_cbc(),plaintext,  plaintext_len, key, iv, ciphertext );
}

int aes_128_cbc_decrypt(uchar **plaintext, int ciphertext_len, uchar *key, uchar *iv, uchar *ciphertext)
{
    return sym_decrypt(EVP_aes_128_cbc(),plaintext,  ciphertext_len, key, iv, ciphertext );
}


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
                    uchar **iv,  uchar **ciphertext){
    const EVP_CIPHER *cypher=AUTH_ENCRYPT_DEFAULT;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == nullptr)    { 
        perror("Error: unallocated context\n");
        return 0;
    }
    int block_len = EVP_CIPHER_block_size(cypher);
    int iv_len = EVP_CIPHER_iv_length(cypher);
    int tag_len=16;

    if(plaintext_len > INT_MAX -block_len) { 
        perror("Error: integer overflow (meggase too big?)\n");
        return 0;
    }

    // allocate buffers
    *tag=(uchar*) malloc(tag_len); 
    if(*tag==nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }
    *ciphertext = (uchar*) malloc(plaintext_len+block_len);
    if(*ciphertext==nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }
    *iv = (uchar*) malloc(iv_len);
    if(iv == nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }

    // generate random IV
    RAND_poll();
    if(1 != RAND_bytes(*iv, iv_len)) { 
        perror("Error: RAND_bytes failed\n");
        return 0;
    }

    /* Create and initialize the context */
    int len;
    int ciphertext_len;
    if(ctx == nullptr)    { 
        perror("Error: unallocated context\n");
        return 0;
    }

    // Encrypt init
    if(1 != EVP_EncryptInit(ctx,cypher, key, *iv)) { 
        perror("Error: encryption init failed\n");
        return 0;
    }

    // Encrypt Update: first call
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) { 
        perror("Error: encryption update1 failed\n");
        return 0;
    }

    // Encrypt Update: second call
    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) { 
        perror("Error: encryption update2 failed\n");
        return 0;
    }
    ciphertext_len = len;

    //Encrypt Final. Finalize the encryption and adds the padding
    if(1 != EVP_EncryptFinal(ctx, *ciphertext + len, &len)) { 
        perror("Error: encryption final failed\n");
        return 0;
    }
    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG, tag_len, *tag)){ 
        perror("Error: encryption ctrl failed\n");
        return 0;
    }

    // deallocate contxt
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

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
                    uchar *iv,  uchar **plaintext){
    const EVP_CIPHER *cypher=AUTH_ENCRYPT_DEFAULT;
    int block_len = EVP_CIPHER_block_size(cypher);
    int iv_len = EVP_CIPHER_iv_length(cypher);
    int tag_len=16;

    if(ciphertext_len > INT_MAX -block_len) { 
        perror("Error: integer overflow (meggase too big?)\n");
        return 0;
    }

    // allocate buffers
    *plaintext = (uchar*) malloc(ciphertext_len+block_len);
    if(*plaintext==nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }

    /* Create and initialize the context */
    int len;
    int plaintext_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == nullptr)    { 
        perror("Error: unallocated context\n");
        return 0;
    }

    // Encrypt init
    if(1 != EVP_DecryptInit(ctx,cypher, key, iv)) { 
        perror("Error: decryption init failed\n");
        return 0;
    }

    // Encrypt Update: first call
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) { 
        perror("Error: decryption update1 failed\n");
        return 0;
    }

    // Encrypt Update: second call
    if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) { 
        perror("Error: decryption update2 failed\n");
        return 0;
    }
    plaintext_len = len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG, tag_len, tag)){ 
        perror("Error: decryption ctrl failed\n");
        return 0;
    }

    //Encrypt Final. Finalize the encryption and adds the padding
    int ret= EVP_DecryptFinal(ctx, *plaintext + len, &len);
    if(ret<0){ 
        perror("Error: decryption final failed \n");
        return 0;
    }
    plaintext_len += len;

    // deallocate contxt
    EVP_CIPHER_CTX_cleanup(ctx);

    return plaintext_len;    
}

/**
 * @brief digest computation
 * 
 * @param cypher input
 * @param plaintext input
 * @param plaintext_len input
 * @param ciphertext output
 * @return digest length, 0 on error
 */
uint digest(const EVP_MD* cypher, uchar* plaintext, uint plaintext_len, uchar** ciphertext){

    if(plaintext_len>BUFFER_MAX){
        perror("Error: buffer too big\n");
        return 0;
    }

    if(cypher==nullptr) { 
        perror("Error: unallocated cypher\n");
        return 0;
    }
    uint cipherlen=EVP_MD_size(cypher);

    // allocate buffers
    *ciphertext = (uchar*) malloc(cipherlen);
    if(*ciphertext==nullptr) { 
        errorHandler(MALLOC_ERR);
        return 0;
    }

    uint outlen;
    EVP_MD_CTX* md_ctx;
    md_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md_ctx, cypher)){
        perror("Error: encryption init failed\n");
        return 0;
    }
    if(!EVP_DigestUpdate(md_ctx, plaintext, plaintext_len)){
        perror("Error: encryption update failed\n");
        return 0;
    }
    if(!EVP_DigestFinal(md_ctx, *ciphertext, &outlen)){
        perror("Error: encryption final failed\n");
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);

    if(outlen != cipherlen) return 0;
    return outlen;
}

// CRYPTO_memcmp wrapper
uint digest_compare(const uchar* digest1, const uchar* digest2, const uint len){
   return CRYPTO_memcmp(digest1, digest2,len );
}

// sha 256 wrapper
uint sha_256_digest(uchar* plaintext, uint plaintext_len, uchar** chipertext){
    return digest(EVP_sha256(), plaintext, plaintext_len, chipertext);
}


/**
 * @brief verify a certificate with a self signed CA certificate and ctrl
 * 
 * @param certificate certificate under verification
 * @param CAcertificate self signed CA certificate
 * @param CAcrl self signed CA ctrl
 * @return 1 if succesfull verification, 0 otherwise
 */
int verify_certificate(  X509* certificate,  X509*  CAcertificate,    X509_CRL* CAcrl){
    int ret; // used for return values
   
    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();
    if(!store) { 
        cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        return 0; }
    ret = X509_STORE_add_cert(store, CAcertificate);
    if(ret != 1) { 
        cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        return 0; }
    ret = X509_STORE_add_crl(store, CAcrl);
    if(ret != 1) { 
        cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        return 0; }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { 
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
        return 0; }

    // verify the certificate
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { 
        cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        return 0; }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, certificate, NULL);
    if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        return 0; }
    ret= X509_verify_cert(certvfy_ctx);
    X509_STORE_free(store);
    X509_STORE_CTX_free(certvfy_ctx);
    return ret;
}

int _verify_sing_pubkey(uchar* signature, uint sign_lenght, uchar* document, uint doc_lenght, 
    EVP_PKEY* pubkey){
    
    int ret; // used for return values
    // create the signature context:
    // declare some useful variables:
    const EVP_MD* md = DIEGST_DEFAULT;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return 0; }

    // verify the plaintext:
    // (perform a single update on the whole plaintext, 
    // assuming that the plaintext is not huge)
    ret = EVP_VerifyInit(md_ctx, md);
    if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; EVP_MD_CTX_free(md_ctx); return 0; }
    ret = EVP_VerifyUpdate(md_ctx, document, doc_lenght);  
    if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n";EVP_MD_CTX_free(md_ctx); return 0; }
    ret = EVP_VerifyFinal(md_ctx, signature, sign_lenght, pubkey);
    if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
        ret=0;
    }
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

int verify_sign_pubkey(uchar* signature, uint sign_lenght, uchar* document, uint doc_lenght, 
    uchar* pubkey, uint key_lenght){
        
    // deserialiaze public key
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, pubkey, key_lenght);
    EVP_PKEY* pkey=PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    int ret=_verify_sing_pubkey(signature, sign_lenght,document, doc_lenght, pkey );
    EVP_PKEY_free(pkey);

    return ret;
}

int verify_sign_cert(const uchar* certificate, const uint cert_lenght,  FILE* const CAcertificate,  
    FILE* const CAcrl, uchar* signature, uint sign_lenght, uchar* document, uint doc_lenght ){
    int ret;

    if(!signature || sign_lenght==0) { cerr << "Error: no signature \n"; return 0; }
    if(!document || doc_lenght==0) { cerr << "Error: no document \n"; return 0; }
    if(!certificate || cert_lenght==0) { cerr << "Error: no certificate \n"; return 0; }

    // load the certificate under validation
    X509* cert=d2i_X509(NULL,   &certificate ,cert_lenght);
    if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; return 0; }
    
    // load CA certificate (self signed)
    if(!CAcertificate){ cerr << "Error: cannot open ca certificate file (missing?)\n"; return 0; }
    X509* cacert = PEM_read_X509(CAcertificate, NULL, NULL, NULL);
    fclose(CAcertificate);
    if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; return 0; }

    // load CA ctrl for revocation list
    if(!CAcrl){ cerr << "Error: cannot open ca ctrl file (missing?)\n"; return 0; }
    X509_CRL* crl = PEM_read_X509_CRL(CAcrl, NULL, NULL, NULL);
    fclose(CAcrl);
    if(!crl){ cerr << "Error: PEM_read_X509_CRL returned NULL\n"; return 0; }
  

    if(!verify_certificate( cert,  cacert, crl)){
        perror("certificate validation failed, the certificate is not valid");
        X509_free(cacert); 
        X509_CRL_free(crl); 
        X509_free(cert);
        return 0;
    }

    // verify the signature with extracted public key
    ret=_verify_sing_pubkey(signature, sign_lenght, document, doc_lenght,X509_get_pubkey(cert) );
    X509_free(cacert); 
    X509_CRL_free(crl); 
    X509_free(cert);
    return ret;
}
// it's possible to permfor encryption/decryption without direct calling openSSL library
/*
int main(){
    cout <<"test";
    string cacert_file_name="certification/SuperHakerCA_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
    
    string crl_file_name="certification/SuperHakerCA_crl.pem";
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
    string cert_file_name="certification/SecureCom_cert.pem";
    FILE* cert_file = fopen(cert_file_name.c_str(), "r");
    
    X509* verified_cert;
    if(verify_certificate(cert_file, cacert_file, crl_file,&verified_cert )){
        char* tmp = X509_NAME_oneline(X509_get_subject_name(verified_cert), NULL, 0);
        char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(verified_cert), NULL, 0);
        cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
        free(tmp);
        free(tmp2);
        cout <<"test";
    }
    X509_free(verified_cert);
   

}
*/
/*
int main(){

    uchar key[] = "0123456789abcdeF";
    uchar plaintext[]="plaintext!=?PLAINTEXT1234";  

    // those are going to be allocated by the crypto API
    uchar* plainres;
    uchar* iv;
    uchar* ciphertext;

    int plain_len= aes_128_cbc_encrypt(plaintext, 26, key, &iv, &ciphertext);
    aes_128_cbc_decrypt(&plainres, plain_len, key, iv, ciphertext);
    cout <<plainres;
    cout<<"\n";

    uchar aad[]="abc";
    uchar* tag;
    cipher_len= aes_gcm_encrypt(plaintext, 26, aad, 4, key, &tag,&iv, &ciphertext);
    cout<<"CT:"<<endl;
	BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
	cout<<"Tag:"<<endl;
	BIO_dump_fp (stdout, (const char *)tag, 16);
    aes_gcm_decrypt(ciphertext, cipher_len,aad, 4, key, tag, iv, &plainres);
    cout<<"PT:"<<endl;
	BIO_dump_fp (stdout, (const char *)plainres, 26);
    cout <<plainres;
    cout<<"\n";

    // free it's necessary after usage
    free(iv);
    free(ciphertext);
    free(plainres);
    free(tag);



}
*/

