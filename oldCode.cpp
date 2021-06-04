
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