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
#include "crypto.h"
#include <openssl/err.h> // for error descriptions

using uchar=unsigned char;
using namespace std;

// print a key, useful for debug
void print_key(EVP_PKEY* key){
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_public(bp, key, 1, NULL);
    BIO_free(bp);
}

uint serialize_pubkey(EVP_PKEY* pubkey, uchar** pubkey_ser){
    BIO* mbio= BIO_new(BIO_s_mem());
    if(!mbio){ cerr << "Error: cannot initialize BIO\n"; return 0;  }
    if(!PEM_write_bio_PUBKEY(mbio, pubkey)){
        cerr << "Error: unable to write in BIO\n"; 
        BIO_free(mbio);
        return 0; }
    uchar* tmp=NULL;

    // obtain size and allocate buffer
    int ret= BIO_get_mem_data(mbio,&tmp);
    *pubkey_ser=(uchar*)malloc(ret);
    if(*pubkey_ser==NULL){ 
        cerr << "unable to allocate buffer for serialized pubkey\n"; 
        BIO_free(mbio);
        return 0;  
    }
    memcpy(*pubkey_ser, tmp, ret);
    BIO_free(mbio);
    return ret;
}

int deserialize_pubkey(const uchar* pubkey_ser, uint key_lenght, EVP_PKEY** pubkey){
    BIO* mbio= BIO_new(BIO_s_mem());
    if(!mbio){ cerr << "Error: cannot initialize BIO\n"; return 0;  }
    if(! BIO_write(mbio, pubkey_ser, key_lenght)){
        cerr << "Error: unable to write in BIO\n"; 
        BIO_free(mbio);
        return 0; }
    *pubkey = PEM_read_bio_PUBKEY( mbio, NULL, NULL, NULL);
    BIO_free(mbio);
    if(*pubkey==nullptr) {cerr << "Error: bio read returned null\n"; return 0; }
    return 1;
}

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


int auth_enc_encrypt( uchar *plaintext, int plaintext_len, uchar* aad, uint aad_len, uchar *key, uchar** tag,
                    uchar **iv,  uchar **ciphertext){
    /* Create and initialize the context */
    const EVP_CIPHER *cypher=AUTH_ENCRYPT_DEFAULT;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == nullptr)    { 
        perror("Error: unallocated context\n");
        return 0;
    }
    int block_len = EVP_CIPHER_block_size(cypher);
    int iv_len = EVP_CIPHER_iv_length(cypher);
    int tag_len=TAG_DEFAULT;


    if(plaintext_len > INT_MAX -block_len) { 
        perror("Error: integer overflow (meggase too big?)\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // allocate buffers
    *tag=(uchar*) malloc(tag_len); 
    if(*tag==nullptr) { 
        errorHandler(MALLOC_ERR);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *ciphertext = (uchar*) malloc(plaintext_len+block_len);
    if(*ciphertext==nullptr) { 
        errorHandler(MALLOC_ERR);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    *iv = (uchar*) malloc(iv_len);
    if(iv == nullptr) { 
        errorHandler(MALLOC_ERR);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // generate random IV
    RAND_poll();
    if(1 != RAND_bytes(*iv, iv_len)) { 
        perror("Error: RAND_bytes failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    int ciphertext_len;

    // Encrypt init
    if(1 != EVP_EncryptInit(ctx,cypher, key, *iv)) { 
        perror("Error: encryption init failed\n");
        
        return 0;
    }

    // Encrypt Update: first call
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) { 
        perror("Error: encryption update1 failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Encrypt Update: second call
    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) { 
        perror("Error: encryption update2 failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;

    //Encrypt Final. Finalize the encryption and adds the padding
    if(1 != EVP_EncryptFinal(ctx, *ciphertext + len, &len)) { 
        perror("Error: encryption final failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG, tag_len, *tag)){ 
        perror("Error: encryption ctrl failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    // deallocate contxt
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int auth_enc_decrypt(uchar *ciphertext, uint ciphertext_len, uchar* aad, uint aad_len, uchar *key, uchar* tag,
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
        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
    }

    // Encrypt Update: first call
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) { 
        perror("Error: decryption update1 failed\n");

        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
    }

    // Encrypt Update: second call
    if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) { 
        perror("Error: decryption update2 failed\n");

        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
    }
    plaintext_len = len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG, tag_len, tag)){ 
        perror("Error: decryption ctrl failed\n");

        EVP_CIPHER_CTX_cleanup(ctx);
        return 0;
    }

    //Encrypt Final. Finalize the dencryption
    int ret= EVP_DecryptFinal(ctx, *plaintext + len, &len);
    if(ret<=0){ 
        perror("Error: decryption final failed \n");
        EVP_CIPHER_CTX_cleanup(ctx);
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
        free(ciphertext);
        return 0;
    }
    if(!EVP_DigestUpdate(md_ctx, plaintext, plaintext_len)){
        perror("Error: encryption update failed\n");
        free(ciphertext);
        return 0;
    }
    if(!EVP_DigestFinal(md_ctx, *ciphertext, &outlen)){
        perror("Error: encryption final failed\n");
        free(ciphertext);
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

uint default_digest(uchar* plaintext, uint plaintext_len, uchar** chipertext){
    return digest(DIGEST_DEFAULT, plaintext, plaintext_len, chipertext);
}

int serialize_certificate(FILE* cert_file, uchar** certificate){

    *certificate=nullptr;
    if(!cert_file){ cerr << "Error: cannot open certificate file (missing?)\n"; return 0; }
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; return 0;  }
    int ret=i2d_X509(cert, certificate);
    X509_free(cert);
    return ret;
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
         X509_STORE_free(store); return 0; }
    ret = X509_STORE_add_crl(store, CAcrl);
    if(ret != 1) { 
        cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
         X509_STORE_free(store); return 0; }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { 
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n";
         X509_STORE_free(store); return 0; }

    // verify the certificate
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { 
        cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
         X509_STORE_free(store); return 0; }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, certificate, NULL);
    if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; 
        ret=0; goto finish; }
    ret= X509_verify_cert(certvfy_ctx);
finish:
    X509_STORE_free(store);
    X509_STORE_CTX_free(certvfy_ctx);
    return ret;
}

int _verify_sing_pubkey(uchar* signature, uint sign_lenght, uchar* document, uint doc_lenght, 
    EVP_PKEY* pubkey){
    
    int ret; // used for return values
    // create the signature context:
    // declare some useful variables:
    const EVP_MD* md = DIGEST_DEFAULT;
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
        
    EVP_PKEY* pkey;
    if(!deserialize_pubkey(pubkey, key_lenght, &pkey)){
        cerr << "Error: unable t odeserialize pubkey \n"; return 0;
    }
    int ret=_verify_sing_pubkey(signature, sign_lenght,document, doc_lenght, pkey );
    EVP_PKEY_free(pkey);

    return ret;
}

int verify_sign_pubkey(uchar* signature, uint sign_lenght, uchar* document, uint doc_lenght, 
    FILE*pubkey){

    EVP_PKEY* pkey=PEM_read_PUBKEY(pubkey,NULL,NULL,NULL) ;     
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
    if(!CAcertificate){ 
        cerr << "Error: cannot open ca certificate file (missing?)\n"; X509_free(cert); return 0; }
    X509* cacert = PEM_read_X509(CAcertificate, NULL, NULL, NULL);
    if(!cacert){ X509_free(cert); cerr << "Error: PEM_read_X509 returned NULL\n"; return 0; }

    // load CA ctrl for revocation list
    if(!CAcrl){ cerr << "Error: cannot open ca ctrl file (missing?)\n"; 
        X509_free(cacert); X509_free(cert); return 0; }
    X509_CRL* crl = PEM_read_X509_CRL(CAcrl, NULL, NULL, NULL);
    if(!crl){ cerr << "Error: PEM_read_X509_CRL returned NULL\n"; 
        X509_free(cacert); X509_free(cert); return 0; }
  

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

int sign_document( const uchar* document, uint doc_lenght, FILE* const priv_key, char* const password, 
        uchar** signature, uint* sign_lenght){
    void* pkey=read_privkey(priv_key,password );
    int ret=sign_document(document, doc_lenght, pkey, signature, sign_lenght);
    safe_free_privkey(pkey);
    return ret;
        
}

int sign_document( const uchar* document, uint doc_lenght, void* priv_key, uchar** signature, uint* sign_lenght){
    EVP_PKEY* prvkey = (EVP_PKEY*)priv_key;
    if(!prvkey){ cerr << "Error:no private key\n"; return 0; }
    if(!document || doc_lenght==0) { cerr << "Error: no document \n"; return 0; }

    // declare some useful variables:
    int ret;
    const EVP_MD* md = DIGEST_DEFAULT;

    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; return 0; }

    // allocate buffer for signature:
    *signature = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
    if(!*signature) { 
        cerr << "Error: malloc returned NULL (signature too big?)\n";
        EVP_MD_CTX_free(md_ctx);
        return 0; 
    }

    // sign the plaintext:
    // (perform a single update on the whole plaintext, 
    // assuming that the plaintext is not huge)
    ret = EVP_SignInit(md_ctx, md);
    if(ret == 0){ cerr << "Error: EVP_SignInit returned " << ret << "\n"; 
        EVP_MD_CTX_free(md_ctx); return 0; }
    ret = EVP_SignUpdate(md_ctx, document, doc_lenght);
    if(ret == 0){ cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; 
        EVP_MD_CTX_free(md_ctx); return 0; }
    ret = EVP_SignFinal(md_ctx, *signature, sign_lenght, prvkey);
    if(ret == 0){ cerr << "Error: EVP_SignFinal returned " << ret << "\n";
        EVP_MD_CTX_free(md_ctx); return 0; }

    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    return 1;
}

int eph_key_generate(void** privkey, uchar** pubkey, uint* pubkey_len ){

    EVP_PKEY* dh_params = NULL;
    EVP_PKEY* priv_key=NULL;
    EVP_PKEY_CTX* pctx;

    // using elliptic-curve
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!pctx){cerr << "Error: unable to allocate EC generation context";return 0;}
    if(!EVP_PKEY_paramgen_init(pctx)){
        cerr << "Error: unable to initialize EC parameters generation";
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    if(!EVP_PKEY_paramgen(pctx, &dh_params)){
        cerr << "Error: unable to generate EC parameters";
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }
    EVP_PKEY_CTX_free(pctx);

    // using DH keys
    EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new(dh_params, NULL);
    if(!ctx){cerr << "Error: unable to allocate DH context";EVP_PKEY_free(dh_params);return 0;}
    if(1!=EVP_PKEY_keygen_init(ctx)){
        cerr << "Error: unable to initialize DH context";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh_params);
        return 0;
    }
    if(1!=EVP_PKEY_keygen(ctx, &priv_key)){
        cerr << "Error: unable to generate DH keys";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(dh_params);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);
  
    // serialize public key
    *pubkey_len= serialize_pubkey(priv_key, pubkey);
    if(!*pubkey){cerr << "Error: unable to serialize DH keys\n";return 0;}
    *privkey=(void*) priv_key; 
    
    return 1;
}

uint derive_secret(void* privkey, uchar* peer_key, uint peer_key_len , uchar** secret ){
    EVP_PKEY_CTX *derive_ctx;
    size_t skeylen=0;

    // deserialize keys
    EVP_PKEY* priv_key=(EVP_PKEY*) privkey;
    EVP_PKEY* peer_pubkey;

    if(!deserialize_pubkey(peer_key, peer_key_len, &peer_pubkey))
        {cerr << "Error: unable to deserialize peer key\n";return 0;}

    // secret derivation
    derive_ctx = EVP_PKEY_CTX_new(priv_key,NULL);
    if (!derive_ctx) {cerr << "Error: unable to allocate DH derivation context";goto finish;}
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) 
        {cerr << "Error: unable to initialize DH derivation context"; goto finish;}
    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0) 
        {cerr << "Error: unable to set peer public key";goto finish;}
    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    if(!EVP_PKEY_derive(derive_ctx, NULL, &skeylen))
        {cerr << "Error: unable to derive DH secret buffer lenght";goto finish;}   
    /*allocate buffer for the shared secret*/
    *secret = (uchar*)(malloc(int(skeylen)));
    if (!*secret){cerr << "Error: unable to allocate DH secret buffer";goto finish;}
    /*Perform again the derivation and store it in skey buffer*/
    if (EVP_PKEY_derive(derive_ctx, *secret, &skeylen) <= 0) 
        {cerr << "Error: unable to derive DH secret";skeylen=0; free(secret);goto finish;}
    
    //FREE EVERYTHING INVOLVED WITH THE EXCHANGE
finish:
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_free(priv_key);
    return skeylen;
}

int random_generate(const uint lenght, uchar* nuance){
    
    if(!RAND_poll()){return 0;}
    if(1 != RAND_bytes(nuance, lenght)) { 
        perror("Error: RAND_bytes failed\n");
        return 0;
    }
    return 1;
}

void safe_free_privkey(void* key){
    EVP_PKEY* priv_key=(EVP_PKEY*) key;
    EVP_PKEY_free(priv_key);
}

void safe_free(uchar* buffer, uint buffer_len ){
#pragma optimize("", off)
    memset(buffer, 0, buffer_len);
#pragma optimize("", on)
    free(buffer);
}
void* read_privkey(FILE* privk_file, char* const password){
    if(!privk_file){ cerr << "Error: cannot open private key file  (missing?)\n"; return NULL; }
    EVP_PKEY* prvkey = PEM_read_PrivateKey(privk_file, NULL, NULL, password);
    if(!prvkey){ cerr << "Error: PEM_read_PrivateKey returned NULL\n"; return NULL; }
    return prvkey;
}
/*
int main(int argc, char* argv[]){
    uchar* skey_A;
    uint skey_A_len;
    uchar* skey_B;
    uint skey_B_len;
    uchar* pubkeyA;
    uint pubkeyA_len;
    uint pubkeyB_len;
    uchar* pubkeyB;
    void* privkeyA;
    void* privkeyB;

    if(!eph_key_generate(&privkeyA, &pubkeyA, &pubkeyA_len)){ cerr<<"ephimeral key generation A failed\n";}
    if(!eph_key_generate(&privkeyB, &pubkeyB, &pubkeyB_len)){ cerr<<"ephimeral key generation B failed\n";}
    
    if(!(skey_A_len=derive_secret(privkeyA, pubkeyB, pubkeyB_len, &skey_A)))
        { cerr<<"secret derivation A failed\n";}
    if(!(skey_B_len=derive_secret(privkeyB, pubkeyA, pubkeyA_len, &skey_B)))
        { cerr<<"secret derivation B failed\n";}

    printf("Here it is A shared secret: \n");
    BIO_dump_fp (stdout, (const char *)skey_A, skey_A_len);
    printf("Here it is B shared secret: \n");
    BIO_dump_fp (stdout, (const char *)skey_B, skey_B_len);
    
    free(pubkeyA);
    free(pubkeyB);
    free(skey_A);
    free(skey_B);
    printf("ok\n");

}
*/
// it's possible to permfor encryption/decryption without direct calling openSSL library
/*
int main(int argc, char* argv[]){
    string cacert_file_name="certification/TrustMe CA_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
    string crl_file_name="certification/TrustMe CA_crl.pem";
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
    string cert_file_name="certification/SecureCom_cert.pem";
    FILE* cert_file = fopen(cert_file_name.c_str(), "r");
    string pkey_file="certification/SecureCom_prvkey.pem";
    FILE* privk_file=fopen(pkey_file.c_str(), "r");
   
    uchar* certificate;
    uint cert_len;
    uchar docuemnt  [] ="ABCD1234PLAINTEXT!!";
    uint doc_size=strlen((char*)docuemnt)+1;
    uchar* sign;
    uint sign_len;
    
    if(sign_document(docuemnt, doc_size, privk_file, &sign, &sign_len)){
        
        cert_len=serialize_certificate(cert_file, &certificate);
        
        if(cert_len!=0){
            int ret= verify_sign_cert(
            certificate, cert_len, cacert_file, crl_file, sign, sign_len, docuemnt, doc_size);
            cout <<"ok";
            cout << "verify_sign_cert returned " << ret << "\n";
        }
        
        free(certificate);
        free(sign);
    }
    return 0;
    
}


int main(){

    uchar key[] = "0123456789abcdeF";
    uchar wrong_key[] = "0123456789ffffff";
    uchar plaintext[]="plaintext!=?PLAINTEXT1234";  
    int plaintext_len=26;
    // those are going to be allocated by the crypto API
    uchar* plainres;
    uchar* iv;
    uchar* ciphertext;

    // authenticated data to be sent in the clear
    uchar auth_clear[]="abc";
    int ac_len=4;

    // compose aad with cyphertext lenght, (equal of plaintext lenght when using GCM)
    uchar* aad=(uchar*)malloc(ac_len+sizeof(int));
    memcpy(aad,auth_clear, ac_len );
    memcpy(aad+ac_len, &plaintext_len, sizeof(int));
    uint aad_len=ac_len+sizeof(int);
;
    uchar* tag;
    int cipher_len= auth_enc_encrypt(plaintext, plaintext_len, aad, aad_len, key, &tag,&iv, &ciphertext);
    cout<<"CT:"<<endl;
	BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
	cout<<"Tag:"<<endl;
	BIO_dump_fp (stdout, (const char *)tag, 16);
    int ret=auth_enc_decrypt(ciphertext, cipher_len,aad, aad_len, wrong_key, tag, iv, &plainres);
    if(!ret)
        cout<<"wrong key!"<<endl;
    else{
        cout<<"PT:"<<endl;
	    BIO_dump_fp (stdout, (const char *)plainres, 26);
        cout <<plainres;
        cout<<"\n";
        free(plainres);
    }

    // free it's necessary after usage
    free(aad);
    free(iv);
    free(ciphertext);
    
    free(tag);



}

*/
