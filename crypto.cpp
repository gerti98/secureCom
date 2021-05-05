#include <stdlib.h>
#include <iostream>
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
using uchar=unsigned char;
using namespace std;
const int fragment_size=1024;

// generic encryption function
int sym_encrypt(const EVP_CIPHER *cypher, uchar *plaintext, int plaintext_len, uchar *key, 
    uchar **iv,  uchar **ciphertext){
    
    if(cypher==nullptr) { 
        cerr <<"Error: unallocated cypher\n";
        return 0;
    }
  
    int block_len = EVP_CIPHER_block_size(cypher);
    int iv_len = EVP_CIPHER_iv_length(cypher);
    if(plaintext_len > INT_MAX -block_len) { 
        cerr <<"Error: integer overflow (meggase too big?)\n";
        return 0;
    }

    // allocate buffers
    *ciphertext = (uchar*) malloc(plaintext_len+block_len);
    if(ciphertext==nullptr) { 
        cerr <<"Error: unallocated buffer\n";
        return 0;
    }
    *iv = (uchar*) malloc(iv_len);
    if(iv == nullptr) { 
        cerr <<"Error: unallocated buffer\n";
        return 0;
    }

    // generate random IV
    RAND_poll();
    if(1 != RAND_bytes(*iv, iv_len)) { 
        cerr <<"Error: RAND_bytes failed\n";
        return 0;
    }

    /* Create and initialize the context */
    int len;
    int ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == nullptr)    { 
        cerr <<"Error: unallocated context\n";
        return 0;
    }

    // Encrypt init
    if(1 != EVP_EncryptInit(ctx,cypher, key, *iv)) { 
        cerr <<"Error: encryption init failed\n";
        return 0;
    }

    // Encrypt Update: one call is enough 
    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) { 
        cerr <<"Error: encryption update failed\n";
        return 0;
    }
    ciphertext_len = len;

    //Encrypt Final. Finalize the encryption and adds the padding
    if(1 != EVP_EncryptFinal(ctx, *ciphertext + len, &len)) { 
        cerr <<"Error: encryption final failed\n";
        return 0;
    }
    ciphertext_len += len;

    // deallocate contxt
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// generic encryption function
int sym_decrypt(const EVP_CIPHER *cypher, uchar **plaintext, int ciphertext_len, uchar *key, 
    uchar *iv, uchar *ciphertext){

    if(cypher==nullptr) { 
        cerr <<"Error: unallocated cypher\n";
        return 0;
    }
  
    int block_len = EVP_CIPHER_block_size(cypher);
    int iv_len = EVP_CIPHER_iv_length(cypher);

    if(iv == nullptr) { 
        cerr <<"Error: unallocated buffer\n";
        return 0;
    }
    
    // allocate buffers
    *plaintext = (uchar*) malloc(ciphertext_len);
    if(*plaintext==nullptr) { 
        cerr <<"Error: unallocated buffer\n";
        return 0;
    }
    EVP_CIPHER_CTX *ctx;
    int len;
    int plainlen;
    int res;

    /* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == nullptr)    { 
        cerr <<"Error: unallocated context\n";
        return 0;
    }

    /* Decryption (initialization + single update + finalization */
    if(1 != EVP_DecryptInit(ctx, cypher, key, iv)){ 
        cerr <<"Error: decrypt init failed\n";
        return 0;
    }
    if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)){ 
        cerr <<"Error: decrypt update failed\n";
        return 0;
    }
    plainlen=len;
    if(1 != EVP_DecryptFinal(ctx, *plaintext + len, &len)){ 
        cerr <<"Error: decrypt update failed\n";
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

// it's possible to permfor encryption/decryption without direct calling openSSL library
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

    // free it's necessary after usage
    free(iv);
    free(ciphertext);
    free(plainres);

}
*/
