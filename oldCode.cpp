
int retrieve_my_userID(int socket)
/* uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT;
    cout << " DBG - header_len: " << header_len << endl;
    unsigned char* header = (unsigned char*)malloc(header_len);
    if(!header){
        cerr << " Error in malloc for header " << endl; 
        return -1;
    }
    unsigned char* iv = (unsigned char*)malloc(IV_DEFAULT);
    if(!iv){
        cerr << " Error in malloc for iv " << endl; 
        free(header);
        return -1;
    }
    unsigned char* tag = (unsigned char*)malloc(TAG_DEFAULT);
    if(!tag){
        cerr << " Error in malloc for tag " << endl; 
        free(header);
        free(iv);
        return -1;
    }
    uint32_t ct_len;
    unsigned char* ciphertext = NULL;
    unsigned char* plaintext = NULL;
    uint32_t pt_len;
    int ret;

    // Receive Header
    //cout << " DBG - Before recv " << endl;
    //BIO_dump_fp(stdout, (const char*)header, header_len);

    ret = recv(sock_id, (void*)header, header_len, 0);
    if(ret <= 0 || ret != header_len){
        cerr << " Error in header reception " << ret << endl;
        BIO_dump_fp(stdout, (const char*)header, header_len);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }
    BIO_dump_fp(stdout, (const char*)header, header_len);
    // Open header
    memcpy((void*)&ct_len, header, sizeof(uint32_t));
    cout << " ct_len :" << endl;
    BIO_dump_fp(stdout, (const char*)&ct_len, sizeof(uint32_t));

    memcpy(iv, header+sizeof(uint32_t), IV_DEFAULT);
    cout << " iv :" << endl;
    BIO_dump_fp(stdout, (const char*)iv, IV_DEFAULT);

    memcpy(tag, header+sizeof(uint32_t)+IV_DEFAULT, TAG_DEFAULT);
    cout << " tag " << endl;
    BIO_dump_fp(stdout, (const char*)tag, TAG_DEFAULT);

    unsigned char* aad = (unsigned char*)malloc(sizeof(uint32_t));
    if(!aad){
        cerr << " Error in aad malloc " << endl;
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }
    memcpy(aad, header, sizeof(uint32_t));
    cout << " AAD : " << endl;
    BIO_dump_fp(stdout, (const char*)aad, sizeof(uint32_t));

    // Receive ciphertext
    cout << " DBG - ct_len before ntohl is " << ct_len << endl;
    ct_len = ntohl(ct_len);
    cout << " DBG - ct_len real is " << ct_len << endl;

    ciphertext = (unsigned char*)malloc(ct_len);
    if(!ciphertext){
        cerr << " Error in malloc for ciphertext " << endl;
        free(header);
        free(tag);
        free(iv);
        return -1;
    }
    ret = recv(sock_id, (void*)ciphertext, ct_len, 0);
    if(ret <= 0){
        cerr << " Error in AAD reception " << endl;
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }

 
    cout << " ciphertext is: " << endl;
    BIO_dump_fp(stdout, (const char*)ciphertext, ct_len);
    // Decryption
    cout<<"Session key:"<<endl;
    BIO_dump_fp(stdout, (const char*) session_key_clientToServer, 32);
    pt_len = auth_enc_decrypt(ciphertext, ct_len, aad, sizeof(uint32_t), session_key_clientToServer, tag, iv, &plaintext);
    if(pt_len == 0 || pt_len!=ct_len){
        cerr << " Error during decryption " << endl;
        free(ciphertext);
        free(plaintext);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }
    cout << " ciphertext is: " << endl;
    BIO_dump_fp(stdout, (const char*)ciphertext, ct_len);
    cout << " plaintext is " << endl;
    BIO_dump_fp(stdout, (const char*)plaintext, pt_len);
    free(ciphertext);
    free(header);
    free(tag);
    free(iv);*/



/**
 * @brief It performs the authentication procedure with the server
 * 
 * @param sock_id socket id
 * @return int 
 */ 
// OLD AUH
int authentication(int sock_id)
{
    bool tooBig = false;                    // indicates if the username inserted by the user is too big
    unsigned char* nonce = NULL;            // nonce R
    unsigned char* server_nonce = NULL;     // nonce R2 from the server
    uint32_t usernameSize;              
    uint32_t net_usernameSize;
    uint16_t size_to_allocate;          
    size_t msg_bytes_written;               // how many byte of the messagge I have been written
    int ret;
    unsigned char* name = NULL;
    unsigned char* msg_auth_1 = NULL;

    int dh_pub_srv_key_size;
    unsigned char* dh_server_pubkey = NULL;

    uint32_t len_signature;
    uint32_t len_signed_msg;
    unsigned char* signed_msg = NULL;
    unsigned char* signature = NULL;

    uint32_t cert_length;
    unsigned char* server_cert = NULL;  

    // Acquire the username from stdin
    do{
        if(tooBig)
            cout << " The username inserted is too big! " << endl;
        cout << " Who are you? " << endl;
        cout << " > ";
        cin >> loggedUser;
        if(loggedUser.size()+1>MAX_USERNAME_SIZE)
            tooBig = true;
    }while(tooBig);

    /*************************************************************
     * M1 - Send R,username to the server
     *************************************************************/
    // Nonce Generation
    cout << " DBG - Nonce generation " << endl;
    nonce = (unsigned char*)malloc(NONCE_SIZE);
    if(!nonce)
        return -1;
    random_generate(NONCE_SIZE, nonce);
    cout << " DBG - Nonnce generated: " << endl;
    BIO_dump_fp(stdout, (const char*)nonce, NONCE_SIZE);

    // Preparation of the username
cout << " DBG - Preparation of the usename " << endl;
    usernameSize = loggedUser.size()+1; // +1 for string terminator
    name = (unsigned char*)malloc(usernameSize);
    if(!name){
        free(nonce);
        return -1;
    }
    net_usernameSize = htonl(usernameSize);
    strncpy((char*)name, loggedUser.c_str(), usernameSize);
    name[usernameSize-1] = '\0'; // to avoid error in strncpy

    // Composition of the message: OPCODE, R, USERNAME_SIZE, USERNAME
cout << " DBG - Composition of the message " << endl;
    size_to_allocate = NONCE_SIZE+sizeof(uint32_t)+usernameSize;
    msg_auth_1 = (unsigned char*)malloc(size_to_allocate);
    if(!msg_auth_1){
        free(name);
        free(nonce);
        return -1;
    }
    memcpy(msg_auth_1, nonce, NONCE_SIZE);
    msg_bytes_written = NONCE_SIZE;
    memcpy(msg_auth_1+msg_bytes_written, &net_usernameSize, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(msg_auth_1+msg_bytes_written, name, usernameSize);
    msg_bytes_written += usernameSize;

cout << " DBG - M1: " << endl;
    BIO_dump_fp(stdout, (const char*)msg_auth_1, msg_bytes_written);

    // Send the message to the server
cout << " DBG - Sending M1 to server " << endl;
    ret = send(sock_id, (void*)msg_auth_1, msg_bytes_written, 0);
    if(ret<=0 || ret != msg_bytes_written){
        free(msg_auth_1);
        free(name);
        free(nonce);
        return -1;
    }
    // free message and unnecessary stuff
    free(msg_auth_1);
    free(name);

    /*************************************************************
     * M2 - Wait for message from the server
     *************************************************************/
cout << " DBG - Wait for M2" << endl;
    // wait for nonce
    server_nonce = (unsigned char*)malloc(NONCE_SIZE);
    if(!server_nonce){
        free(nonce);
        return -1;
    }
    ret = recv(sock_id, (void*)server_nonce, NONCE_SIZE, 0);  
    if(ret <= 0){
        free(server_nonce);
        free(nonce);
        return -1;
    }
    cout << " DBG - R2 received: " << endl;
    BIO_dump_fp(stdout, (const char*)&server_nonce, NONCE_SIZE);
    // Read the length of the DH server pub key
cout << " DBG - Read length of DH server pub key " << endl;
    ret = recv(sock_id, (void*)&dh_pub_srv_key_size, sizeof(int), 0);  
    if(ret <= 0){
        free(server_nonce);
        free(nonce);
        return -1;
    }
    dh_pub_srv_key_size = ntohl(dh_pub_srv_key_size);

    // Read DH server pub key
cout << " DBG - Read server pubkey for "<< dh_pub_srv_key_size<<" bytes"<< endl;
    dh_server_pubkey = (unsigned char*)malloc(dh_pub_srv_key_size);
    if(!dh_server_pubkey){
        free(server_nonce);
        free(nonce);
    }
    ret = recv(sock_id, (void*)dh_server_pubkey, dh_pub_srv_key_size, 0);  
    if(ret <= 0 || ret != dh_pub_srv_key_size){
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        return -1;
    }
    cout << " DBG - DHpubk_S received: " << endl;
    BIO_dump_fp(stdout, (const char*)&dh_server_pubkey, dh_pub_srv_key_size);
    // Read signature length
cout << " DBG - Read signature length " << endl;
    ret = recv(sock_id, (void*)&len_signature, sizeof(uint32_t), 0);  
    if(ret <= 0 || ret!=sizeof(uint32_t)){
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        return -1;
    }
    len_signature = ntohl(len_signature);

    
    // Read signature
cout << " DBG - Read signature "<< len_signature<<" bytes"<< endl;
    signature = (unsigned char*)malloc(len_signature);
    if(!signature){
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        return -1;
    }
    ret = recv(sock_id, (void*)signature, len_signature, 0);  
    if(ret <= 0 || ret!=len_signature){
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signature);
        return -1;
    }
    
    // Read certificate length
cout << " DBG - Read certificate length " << endl;
    ret = recv(sock_id, (void*)&cert_length, sizeof(uint32_t), 0);  
    if(ret <= 0 || ret!=sizeof(uint32_t)){
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signature);
        return -1;
    }
    cert_length = ntohl(cert_length);

    // Read certificate
cout << " DBG - Read certificate for "<< cert_length<<" bytes"<< endl;
    server_cert = (unsigned char*)malloc(cert_length);
    if(!server_cert){
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signature);
        return -1;
    }
    ret = recv(sock_id, (void*)server_cert, cert_length, 0);  
    if(ret <= 0 || ret!=cert_length){
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signed_msg);
        free(signature);
        free(server_cert);
        return -1;
    }

    // Check the authenticity of the msg
cout << " DBG - Check the authenticity of the msg " << endl;
    len_signed_msg = NONCE_SIZE*2+dh_pub_srv_key_size;
    signed_msg = (unsigned char*)malloc(len_signed_msg);
    if(!signed_msg){
        cerr<<"no msg"<<endl;
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signature);
        free(server_cert);
        return -1;
    }

    memcpy(signed_msg, nonce, NONCE_SIZE);
    memcpy(signed_msg+NONCE_SIZE, server_nonce, NONCE_SIZE);
    memcpy(signed_msg+(2*NONCE_SIZE), dh_server_pubkey, dh_pub_srv_key_size);

    FILE* CA_cert_file = fopen("certification/TrustMe CA_cert.pem","rb");
    if(!CA_cert_file){
        cerr<<"no CA cert"<<endl;
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signed_msg);
        free(signature);
        free(server_cert);
        return -1;
    }
    FILE* CA_crl_file = fopen("certification/TrustMe CA_crl.pem","rb");
    if(!CA_crl_file){
        cerr<<"no CA crl"<<endl;
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signed_msg);
        free(signature);
        free(server_cert);
        fclose(CA_cert_file);
        return -1;
    }

    ret = verify_sign_cert(server_cert, cert_length, CA_cert_file, CA_crl_file, signature, len_signature, signed_msg, len_signed_msg);
    if(ret!=1){
        cout << " The signature is not valid " << endl;
        cerr << "Error: verify_sign_cert returned " << ret << " (invalid signature?)\n";
        free(server_nonce);
        free(nonce);
        free(dh_server_pubkey);
        free(signed_msg);
        free(signature);
        free(server_cert);
        fclose(CA_cert_file);
        fclose(CA_crl_file);
        return -1;
    }
    // Close and free the unnecessary stuff
    fclose(CA_cert_file);
    fclose(CA_crl_file);
    free(signature);
    free(signed_msg);
    free(nonce);

    // Verify the authenticity of the server pub key ?
    

    /*************************************************************
     *  Generate (DH_pubKey_C, DH_privKey_C)
     *************************************************************/
cout << " DBG - Generating DH pair " << endl;
    void* eph_dh_privKey = NULL;
    unsigned char* eph_dh_pubKey = NULL; 
    uint32_t eph_dh_pubKey_len;   
    ret = eph_key_generate(&eph_dh_privKey, &eph_dh_pubKey, &eph_dh_pubKey_len);
    if(ret!=1){
        cerr<<"error generating eph keys"<<endl;
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        return -1;
    }

    /*************************************************************
     * M3 - Send to the server my DHpubKey and the nonce R2
     *************************************************************/
    // Preparation of the message to sign
cout << " DBG - Preparing M3 " << endl;
    uint32_t msg_to_sign_len = NONCE_SIZE+eph_dh_pubKey_len;
    unsigned char* msg_to_sign = (unsigned char*)malloc(msg_to_sign_len);
    if(!msg_to_sign){
        cerr<<"error M3 msg to sign malloc failed"<<endl;
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        free(eph_dh_privKey);
        free(eph_dh_pubKey);
        return -1;
    }

    memcpy(msg_to_sign, eph_dh_pubKey,eph_dh_pubKey_len );
    memcpy(msg_to_sign+eph_dh_pubKey_len, server_nonce, NONCE_SIZE);
    

    unsigned char* client_signature = NULL;
    uint32_t client_sign_len;
    string privkey_file_path = "clients_data/"+loggedUser+"/"+loggedUser+"_privkey.pem";
    FILE* privKey_file = fopen(privkey_file_path.c_str(), "rb");
    if(!privKey_file){
        cerr<<"error unable to read privkey file"<<endl;
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        free(msg_to_sign);
        free(eph_dh_privKey);
        free(eph_dh_pubKey);
        return -1;
    }
    ret = sign_document(msg_to_sign, msg_to_sign_len, privKey_file,NULL, &client_signature, &client_sign_len);
    if(ret!=1){
        cerr<<"unable to sign"<<endl;
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        free(msg_to_sign);
        free(eph_dh_privKey);
        free(eph_dh_pubKey);
        fclose(privKey_file);
        return -1;
    }
    
    cerr<<"DBG - sign done"<<endl;
    free(server_nonce);
    free(msg_to_sign);
    fclose(privKey_file);

    // Building the message to send
    uint32_t msglen = sizeof(uint32_t)+eph_dh_pubKey_len+sizeof(uint32_t)+client_sign_len;
    unsigned char* msg_to_send_M3 = (unsigned char*)malloc(msglen);
    if(!msg_to_send_M3){
        free(dh_server_pubkey);
        free(server_cert);
        free(client_signature);
        free(eph_dh_privKey);
        free(eph_dh_pubKey);
        return -1;
    }

    cerr<<"DBG - copyng:"<<endl;
    uint32_t n_eph_dh_pubKey_len=htonl(eph_dh_pubKey_len);
    uint32_t n_client_sign_len=htonl(client_sign_len);
    msg_bytes_written = 0;
    memcpy(msg_to_send_M3 + msg_bytes_written, &n_eph_dh_pubKey_len, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(msg_to_send_M3+ msg_bytes_written, eph_dh_pubKey, eph_dh_pubKey_len);
    cerr<<"DBG - eph pub key: "<<eph_dh_pubKey_len<<" bytes"<<endl;
    msg_bytes_written += eph_dh_pubKey_len;
    memcpy(msg_to_send_M3 + msg_bytes_written, &n_client_sign_len, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(msg_to_send_M3 + msg_bytes_written, client_signature, client_sign_len);
    cerr<<"DBG - signature: "<<client_sign_len<<" bytes"<<endl;
    msg_bytes_written += client_sign_len;
    if(msg_bytes_written != msglen){
        cerr<<"ERR - error on copyng"<<endl;
        free(dh_server_pubkey);
        free(server_cert);
        free(client_signature);
        free(msg_to_send_M3);
        free(eph_dh_privKey);
        free(eph_dh_pubKey);
        return -1;
    }
cout << " DBG - M3 :" << endl;
    BIO_dump_fp(stdout, (const char*)msg_to_send_M3, msglen);

    // Send the message to send to the server
cout << " DBG - Sending M3 " << endl;
    ret = send(sock_id, (void*)msg_to_send_M3, msglen, 0);
    if(ret<=0 || ret != msglen){
        free(dh_server_pubkey);
        free(server_cert);
        free(client_signature);
        free(msg_to_send_M3);
        free(eph_dh_privKey);
        free(eph_dh_pubKey);
        return -1;
    }

    free(msg_to_send_M3);
    free(client_signature);

    /*************************************************************
     * Derive the session key through the master secret
     *************************************************************/
cout << " DBG - Deriving session key " << endl;
    unsigned char* secret = NULL;
    uint32_t secret_len = derive_secret(eph_dh_privKey, dh_server_pubkey, dh_pub_srv_key_size, &secret);
    if(secret_len==0){
        free(dh_server_pubkey);
        free(server_cert);
        free(eph_dh_pubKey);
        return -1;
    }
    
    free(dh_server_pubkey);
    free(eph_dh_pubKey);


    session_key_clientToServer = NULL;
    uint32_t keylen;
    keylen = default_digest(secret, secret_len, &session_key_clientToServer);
    if(keylen==0){
        free(server_cert);
        free(session_key_clientToServer);
        free(secret);
        return -1;
    }
    free(secret);
    cout << "DBG - Session key generated!" << endl;
    BIO_dump_fp(stdout, (const char*)session_key_clientToServer, keylen);
    /************************************************************
     * End of Authentication 
     ************************************************************/
    ret = retrieve_my_userID(sock_id);
    if(ret!=0){
        cerr << " Error during the retrieving of the user id " << endl;
        return -1;
    }
    // If we are arrived here the authentication is done succesfully
    return 0;
}







    /**
 * @brief Handler that handles the SIG_ALARM, this represents the fact that every REQUEST_CONTROL_TIME the client must control for chat request
 *
 * 
 * @param sig 
//  */
// void signal_handler(int sig)
// {
//     // Se viene chiamato durante una comunicazione durante client e server rompe tutto perchè la listen legge un byte dal socket
//    // cout << " DBG - Received signal for controlling the chat request from the server" << endl;
//     uint8_t opcode = NOT_VALID_CMD;
//     uint8_t response;
//     int id_cp;
//     unsigned char* counterpart;
//     int size_username;
//     char user_resp = 'a';
//     unsigned char* risp_buff = NULL;
//     size_t risp_buff_size = 0;

//     int ret = recv(sock_id, (void*)&opcode, sizeof(uint8_t), MSG_DONTWAIT); 
//     if(ret <= 0){
//         //cout << " DBG - nothing received " << endl;
//         alarm(REQUEST_CONTROL_TIME);
//         return;
//     }

//     if(opcode!=CHAT_CMD){
//         if(opcode==CHAT_RESPONSE){
//             cout << " message arrived " << endl;
//         }
//         cout << " DBG - wrong opcode: " << (uint16_t)opcode << endl;
//         alarm(REQUEST_CONTROL_TIME);
//         return;
//     }
    
//     cout << " DBG - Received a chat request " << endl;
//     // Reading of sequence number - not present yet

//     // Reading of the peer id
//     ret = recv(sock_id, (void*)&id_cp, sizeof(int), 0); 
//     if(ret <= 0){
//         cout << " DBG - peer id not received " << endl;
//         alarm(REQUEST_CONTROL_TIME);
//         return;
//     }
//     //id_cp = ntohl(id_cp);
    
//     // Read username length
//     ret = recv(sock_id, (void*)&size_username, sizeof(int), 0); 
//     if(ret <= 0 || size_username==0){
//         cout << " DBG - username length not received " << endl;
//         alarm(REQUEST_CONTROL_TIME);
//         return;
//     }
//     cout << " size: " << size_username << endl;
//     int real_size_username = ntohl(size_username);
//     cout << " size after ntohl " << real_size_username << endl;
//     // Read username peer
//     counterpart = (unsigned char*)malloc(size_username);
//     if(!counterpart){
//         cout << " DBG - malloc error for counterpart " << endl;
//         alarm(REQUEST_CONTROL_TIME);
//         // BUFFER OVERFLOW PROBLEM? RETURN IS ENOUGH?
//         return;
//     }

//     ret = recv(sock_id, (void*)counterpart, size_username, 0); 
//     if(ret <= 0){
//         cout << " DBG - username not received " << endl;
//         alarm(REQUEST_CONTROL_TIME);
//         return;
//     }
//     cout << " cp: " << counterpart << endl;
//     // Read sender pubkey - not present yet


//     if(isChatting){
//         cout << " DBG - Automatic response because I am chatting " << endl;
//         // Automatic response
//         free(counterpart);
//         risp_buff_size = sizeof(uint8_t)+sizeof(int);
//         risp_buff = (unsigned char*)malloc(risp_buff_size);
//         if(!risp_buff){
//             alarm(REQUEST_CONTROL_TIME);
//             // BUFFER OVERFLOW PROBLEM? RETURN IS ENOUGH?
//             return;
//         }
//         response = CHAT_NEG;
//         memcpy(risp_buff, (void*)&response, sizeof(uint8_t));

//         memcpy(risp_buff+1, (void*)&id_cp, sizeof(int));
//         ret = send(sock_id, (void*)risp_buff, risp_buff_size, 0);
//         free(risp_buff);
//         alarm(REQUEST_CONTROL_TIME);
//         return;
//     }

//     peer_id = ntohl(id_cp);
//     peer_username = (char*)counterpart;
//     cout << "\n **********************************************************" << endl;
//     cout << " Do you want to chat with " << peer_username << " with user id " << peer_id << " ? (y/n)" << endl;
//     free(counterpart);
//     while(user_resp!='y' && user_resp!='n') {
//         cin >> user_resp;
//         if(user_resp=='y')
//             response = CHAT_POS;
//         else if (user_resp=='n')
//             response = CHAT_NEG;
//         else    
//             cout << " Wrong format - Please write y if you want to accept, n otherwise " << endl;
//     }

//     risp_buff_size = sizeof(uint8_t)+sizeof(int); // sequence number not considere yet
//     risp_buff = (unsigned char*)malloc(risp_buff_size);
//     if(!risp_buff){
//         alarm(REQUEST_CONTROL_TIME);
//         // BUFFER OVERFLOW PROBLEM? RETURN IS ENOUGH?
//         return;
//     }
    
//     memcpy((void*)risp_buff, (void*)&response, sizeof(uint8_t));
//     // insert sequence number - not present yet
//     memcpy((void*)(risp_buff+1), (void*)&peer_id, sizeof(int));

//     ret = send(sock_id, (void*)risp_buff, risp_buff_size, 0);
//     free(risp_buff);

//     // I am now chatting with the user that request to contact me
//     // Clean stdin by what we have digit previously
//   //  cin.clear();
//     //fflush(stdin);

//     isChatting = true;
//     cout << " ******************************** " << endl;
//     //cout << " Press Enter to enter in the chat section" << endl;
//     cout << " ******************************** " << endl;
//     cout << "               CHAT               " << endl;
//     cout << " All the commands are ignored in this section except for !stop_chat " << endl;
//     cout << " Send a message to " <<  peer_username << " \n > " <<  endl;

//    // cin.putback('c');
//     //cin.clear();
//     //fflush(stdin);
    
//         //    printf(" > ");
//     /*streambuf *backup;
//     string test = "CHAT_STARTED";
//     istringstream oss (test);
//     backup = cin.rdbuf();
//     cin.rdbuf(oss.rdbuf());
//     *///string str;
//     //cin >> str;
//     //cout << "read " << str;



//     //cin.putback
//     //printf(" > ");
//     alarm(REQUEST_CONTROL_TIME);
//     return;
// }