#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <climits>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sstream>
#include "constant.h"
#include "util.h"
#include "crypto.h"


using namespace std;

typedef void (*sighandler_t)(int);



//---------------- GLOBAL VARIABLES ------------------//
/* This global variable is setted to true if the user is in chat with 
 * another client, to false otherwise*/
bool isChatting = false;

/* This global variable is setted to true when an error occurs*/
bool error = false;

/* Username of the "logged" user*/
string loggedUser;

/* Id of the logged user */
int loggedUser_id;

/* ID and username of the user that I am chatting with */
string peer_username;
int peer_id;

/* socket id*/
int sock_id;                           

/* Session key between client and server*/
unsigned char* session_key_clientToServer = NULL;

/* Server certificate */
unsigned char* server_cert = NULL;

//---------------- STRUCTURES ------------------//
struct commandMSG
{
    uint8_t opcode;
    int userId;
};

struct genericMSG
{
    uint8_t opcode;
    uint16_t user_id_recipient;
    uint16_t length;
    unsigned char* payload;
};

struct user
{
    int userId;
    unsigned char* username;
    size_t usernameSize;
    user* next;
};

/* pointer to the list of online users*/
user* user_list = NULL;


/**
 * @brief Print the welcome message
 * 
 */
void welcome()
{
    cout << " *********************************************************************** " << endl;
    cout << "                           SECURE COMMUNICATION " << endl;
    cout << " *********************************************************************** " << endl;
    cout << "   !exit       Close the application" << endl;
    cout << "   !help       See all the possible commands" << endl;
    cout << "-------------------------------------------------------------------------" << endl;
}

/**
 * @brief Print the help command
 * 
 */
void help()
{
    cout << " !users_online" << endl;
    cout << "   Ask the server to return the list of the online users" << endl;
    cout << " !chat" << endl;
    cout << "   Ask the server to start a chat" << endl;
    cout << " !exit" << endl;
    cout << "   Close the application" << endl;
}

/**
 * @brief Command handler
 * 
 * @param cmd string which is the command
 * @return uint8_t opcode
 */
uint8_t commandStringHandler(string cmd)
{
    if(cmd.compare("!exit")==0)
        return EXIT_CMD;
    else if(cmd.compare("!users_online")==0)
        return ONLINE_CMD;
    else if(cmd.compare("!chat")==0)
        return CHAT_CMD;
    else if(cmd.compare("!help")==0)
        return HELP_CMD;
    else if(cmd.compare("!stop_chat")==0)
        return STOP_CHAT;
    else
        return NOT_VALID_CMD;
}

/**
 * @brief Get the Username From the user id
 * 
 * @param userId 
 * @param userlist 
 * @return string that is the username, NULL if error
 */
string getUsernameFromID(int userId, user* userlist)
{ 
    if(userlist==NULL) {
        cout << " Warning: userlist is null " << endl;
        return string();
    }
    struct user* tmp = userlist;
    while(tmp!=NULL) {
        if(tmp->userId==userId) {
            //strncpy((char*)username, (char*)tmp->username, tmp->usernameSize);  
            string username ((char*)(tmp->username)); 
            return username;
        }
        tmp = tmp->next;
    }
    return string();
}


/**
 * @brief Handle the client side part of the command chat
 * 
 * @param toSend 
 * @return int -1 requested user is not in the userlist or userlist is empty, 0 otherwise
 */
int chat(struct commandMSG* toSend, user* userlist)
{
    if(userlist==NULL)
        return -1;
    toSend->opcode = CHAT_CMD; 
    cout << " Write the userID of the user that you want to contact" << endl;
    printf(" > ");
    cin >> toSend->userId;
    peer_id = toSend->userId;
    peer_username = getUsernameFromID(peer_id, userlist);
    cout << " dbg " << endl;
    if(peer_username.empty())
        return -1;
    return 0;
}

/**
 * @brief Free the list of users
 * 
 * @param userlist head of the list that must be cleaned
 */
void free_list_users(struct user* userlist)
{
    if(userlist==NULL)
        return;

    struct user* toDelete = userlist;
    struct user* nextDeletion = NULL;

    while(toDelete!=NULL) {
        nextDeletion = toDelete->next;
        free(toDelete->username);
        free(toDelete);
        toDelete = nextDeletion;
    }
}

/**
 * @brief The function receives from the server the list of the user and it store it
 * 
 * @param sock_id socket id
 * @param userlist data structure to store the list
 * @return The number of online users, -1 if error, 0 if no user in the list
 */
int retrieveOnlineUsers(int sock_id, user*& user_list)
{
    if(user_list!=NULL)
        free_list_users(user_list);
    unsigned int howMany;
    int ret = recv(sock_id, (void*)&howMany, sizeof(int), 0);  
    howMany = ntohl(howMany);
    cout << " DBG - Number of users: " << howMany << endl;
    
    if(ret <= 0)
        return -1;
    if(howMany==0)
        return 0;
    if(howMany>REGISTERED_USERS)
        return -1;

    struct user* current = NULL;
    struct user* tmp = NULL;

    for(int i = 0; i<howMany; i++) {
        cout << " DBG - i: " << i << endl;
        int username_size;
        tmp = (struct user*)malloc(sizeof(user));

        if(!tmp) {
            cout << "Malloc failed " << endl; 
            return -1;
        }

        tmp->username = NULL;
        tmp->userId = -1;
        tmp->next = NULL;
        tmp->usernameSize = 0;

        ret = recv(sock_id, (void*)&(tmp->userId), sizeof(int), 0);  
        tmp->userId = ntohl(tmp->userId);
        cout << " DBG - User id: " << tmp->userId << endl;
        if(ret <= 0) {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }

        ret = recv(sock_id, (void*)&username_size, sizeof(int), 0);  
        if(ret <= 0) {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }
        username_size = ntohl(username_size);
        cout << " DBG - Username size: " << username_size << endl;
        tmp->usernameSize = username_size;
        if(username_size>MAX_USERNAME_SIZE) {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }

        tmp->username = (unsigned char*)malloc(username_size+1);
        if(!tmp->username)
            errorHandler(MALLOC_ERR);
        
        ret = recv(sock_id, (void*)(tmp->username), username_size, 0);  
        if(ret <= 0) {   
            free(tmp->username);
            free(tmp);
            free_list_users(user_list);
            return -1;
        }
        tmp->username[username_size] = '\0';
        cout << " DBG - Username: " << tmp->username << endl;
        if(i==0)
            user_list = tmp;
        else
            current->next = tmp;  
        current = tmp;    
    }
    return howMany;
}


/**
 * @brief Printf the list of users
 * 
 * @param userlist The list of the user that I have to print
 * @return -1 in case of error, 0 otherwise.
 */
int print_list_users(user* userlist)
{
    if(userlist==NULL) {
        cout << " Warning: userlist is null " << endl;
        return -1;
    }
    struct user* tmp = userlist;
    cout << " **** USER LIST **** " << endl;
    cout << "  ID \t Username" << endl;
    while(tmp!=NULL) {
        cout << "  " << tmp->userId << " \t " << tmp->username << endl;
        tmp = tmp->next;
    }
    cout << " ****************** " << endl;
    return 0;
}


/**
 * @brief It is in charge of handlig the sending of a command to the server
 * @param sock_id socket id
 * @param cmdToSend data structure which represent the message to send
 * @return -1 in case of error
 * */
int send_command_to_server(int sock_id, commandMSG* cmdToSend)
{
    uint32_t net_id;
    int ret = send(sock_id,(void*)&cmdToSend->opcode, sizeof(uint8_t), 0);
    if(ret < 0 || ret!=sizeof(uint8_t))
        return -1;
                
    if(cmdToSend->opcode==CHAT_CMD) {
        net_id = htonl(cmdToSend->userId);
        ret = send(sock_id,(void*)&net_id, sizeof(uint32_t), 0);
        if(ret < 0 || ret!=sizeof(uint32_t))
            return -1;
    }
    cout << " DBG - I have sent " << (uint16_t)cmdToSend->opcode << " " << cmdToSend->userId << " aka " << net_id << endl;
    return 0;
}

/**
 * @brief It send the message to the server
 * 
 * @param sock_id socket id
 * @param msgToSend data structure that contains the info for the message
 * @return int 
 */
int send_message(int sock_id, genericMSG* msgToSend)
{
    unsigned char* msg = (unsigned char*)malloc(msgToSend->length+sizeof(uint8_t)+sizeof(uint16_t));
    if(!msg)
        return -1;

    int bytes_allocated = 0;
    uint16_t net_peer_user_id = htons(msgToSend->user_id_recipient);
    uint16_t net_len = htons(msgToSend->length);
    memcpy((void*)msg, &(msgToSend->opcode), sizeof(uint8_t));
    bytes_allocated += sizeof(uint8_t);
    memcpy((void*)(msg+bytes_allocated), &(net_peer_user_id), sizeof(uint16_t));
    bytes_allocated += sizeof(uint16_t);
    memcpy((void*)(msg+bytes_allocated), &(net_len), sizeof(uint16_t));
    bytes_allocated += sizeof(uint16_t);
    memcpy((void*)(msg+bytes_allocated), (void*)(msgToSend->payload), (msgToSend->length));
    bytes_allocated += msgToSend->length;

    BIO_dump_fp(stdout, (const char*)msg, bytes_allocated);

    int ret = send(sock_id, (void*)msg, bytes_allocated, 0);
    if(ret < 0 || ret!=bytes_allocated)
        return -1;

    free(msgToSend->payload);
    free(msg);

    return 0;
}

/**
 * @brief Receive a message sent by the other communication party and forwarded by the server
 * 
 * @param sock_id socket id
 * @param msg string where the received message is inserted
 * @return int -1 id error, 0 otherwise
 */
int receive_message(int sock_id, string& msg)
{
    log("Receive_message");
    uint16_t peer_user_id;
    int ret = recv(sock_id, (void*)&peer_user_id, sizeof(uint16_t), 0); 
    if(ret <= 0)
        return -1;
    
    uint16_t msg_size;
    ret = recv(sock_id, (void*)&msg_size, sizeof(uint16_t), 0); 
    if(ret <= 0)
        return -1;

    uint16_t host_msg_size = ntohs(msg_size);

    // CONTROLLA MSG SIZE PER OVERFLOW
    char* msg_vector = (char*)malloc(host_msg_size);
    if(!msg_vector)
        return -1;

    ret = recv(sock_id, (void*)msg_vector, host_msg_size, 0); 
    if(ret <= 0)
        return -1;

    msg = (string)msg_vector;
    return 0;
}


/**
 * @brief It performs the authentication procedure with the server
 * 
 * @param sock_id socket id
 * @return int 
 */
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
    //fclose(CA_cert_file);
    //fclose(CA_crl_file);
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
    ret = sign_document(msg_to_sign, msg_to_sign_len, privKey_file, &client_signature, &client_sign_len);
    if(ret!=1){
        cerr<<"unable to sign"<<endl;
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        free(msg_to_sign);
        free(eph_dh_privKey);
        free(eph_dh_pubKey);
        return -1;
    }
    cerr<<"DBG - sign done"<<endl;
    free(server_nonce);
    //fclose(privKey_file);
    free(msg_to_sign);
   
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
    memcpy(msg_to_send_M3, &n_eph_dh_pubKey_len, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(msg_to_send_M3, eph_dh_pubKey, eph_dh_pubKey_len);
    cerr<<"DBG - eph pub key: "<<eph_dh_pubKey_len<<" bytes"<<endl;
    msg_bytes_written += eph_dh_pubKey_len;
    memcpy(msg_to_send_M3, &n_client_sign_len, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(msg_to_send_M3, client_signature, client_sign_len);
    cerr<<"DBG - signature: "<<eph_dh_pubKey_len<<" bytes"<<endl;
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
    free(secret);

    session_key_clientToServer = NULL;
    uint32_t keylen;
    keylen = default_digest(secret, secret_len, &session_key_clientToServer);
    if(keylen==0){
        free(server_cert);
        free(session_key_clientToServer);
    }
    
    /************************************************************
     * End of Authentication 
     ************************************************************/
    // At the end of the authentication the server will send the id that he is assigned to me
cout << " DBG - Retrieving user id " << endl;
    // TO DO
    int loggedUser_id_net_ct;
    ret = recv(sock_id, (void*)&loggedUser_id_net_ct, sizeof(int), 0);
    if(ret <= 0)
        return -1;
    
    loggedUser_id = ntohl(loggedUser_id_net_ct);
    cout << " I'm the user with ID " << loggedUser_id << endl;  
    

    // For now let's assume that the authentication has been succesfully executed
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

/**
 * @brief handle an incoming chat request
 * 
 * @param sock_id communication socket
 * @return 1 if everything's ok, 0 on error(s)
 */
int chatRequestHandler(int sock_id){
    int ret;
    uint8_t opcode = NOT_VALID_CMD;
    uint8_t response;
    int id_cp;
    unsigned char* counterpart;
    int size_username;
    char user_resp = 'a';
    unsigned char* risp_buff = NULL;
    size_t risp_buff_size = 0;
    cout << " DBG - Received a chat request " << endl;
    // Reading of sequence number - not present yet

    // Reading of the peer id
    ret = recv(sock_id, (void*)&id_cp, sizeof(int), 0); 
    if(ret <= 0){
        cout << " DBG - peer id not received " << endl;
        alarm(REQUEST_CONTROL_TIME);
        return 0;
    }
    //id_cp = ntohl(id_cp);
    
    // Read username length
    ret = recv(sock_id, (void*)&size_username, sizeof(int), 0); 
    if(ret <= 0 || size_username==0){
        cout << " DBG - username length not received " << endl;
        alarm(REQUEST_CONTROL_TIME);
        return 0;
    }
    cout << " size: " << size_username << endl;
    //int real_size_username = ntohl(size_username);
    //cout << " size after ntohl " << real_size_username << endl;
    // Read username peer
    counterpart = (unsigned char*)malloc(size_username);
    if(!counterpart){
        cout << " DBG - malloc error for counterpart " << endl;
        alarm(REQUEST_CONTROL_TIME);
        // BUFFER OVERFLOW PROBLEM? RETURN IS ENOUGH?
        return 0;
    }

    ret = recv(sock_id, (void*)counterpart, size_username, 0); 
    if(ret <= 0){
        cout << " DBG - username not received " << endl;
        alarm(REQUEST_CONTROL_TIME);
        return 0;
    }
    cout << " cp: " << counterpart << endl;
    // Read sender pubkey - not present yet

    if(isChatting){
        cout << " DBG - Automatic response because I am chatting " << endl;
        // Automatic response
        free(counterpart);
        risp_buff_size = sizeof(uint8_t)+sizeof(int);
        risp_buff = (unsigned char*)malloc(risp_buff_size);
        if(!risp_buff){
            alarm(REQUEST_CONTROL_TIME);
            // BUFFER OVERFLOW PROBLEM? RETURN IS ENOUGH?
            return 0;
        }
        response = CHAT_NEG;
        memcpy(risp_buff, (void*)&response, sizeof(uint8_t));
        memcpy(risp_buff+1, (void*)&id_cp, sizeof(int));
        ret = send(sock_id, (void*)risp_buff, risp_buff_size, 0);
        free(risp_buff);
        alarm(REQUEST_CONTROL_TIME);
        return 0;
    }

    peer_id = ntohl(id_cp);
    peer_username = (char*)counterpart;
    cout << "\n **********************************************************" << endl;
    cout << " Do you want to chat with " << peer_username << " with user id " << peer_id << " ? (y/n)" << endl;
    free(counterpart);
    while(user_resp!='y' && user_resp!='n') {
        cin >> user_resp;
        if(user_resp=='y')
            response = CHAT_POS;
        else if (user_resp=='n')
            response = CHAT_NEG;
        else    
            cout << " Wrong format - Please write y if you want to accept, n otherwise " << endl;
    }

    risp_buff_size = sizeof(uint8_t)+sizeof(int); // sequence number not considere yet
    risp_buff = (unsigned char*)malloc(risp_buff_size);
    if(!risp_buff){
        alarm(REQUEST_CONTROL_TIME);
        // BUFFER OVERFLOW PROBLEM? RETURN IS ENOUGH?
        return 0;
    }
    
    memcpy((void*)risp_buff, (void*)&response, sizeof(uint8_t));
    // insert sequence number - not present yet
    memcpy((void*)(risp_buff+1), (void*)&id_cp, sizeof(int));

    ret = send(sock_id, (void*)risp_buff, risp_buff_size, 0);
    free(risp_buff);

    // I am now chatting with the user that request to contact me
    // Clean stdin by what we have digit previously
    cin.clear();
    fflush(stdin);

    isChatting = true;
    cout << " ******************************** " << endl;
    //cout << " Press Enter to enter in the chat section" << endl;
    cout << " ******************************** " << endl;
    cout << "               CHAT               " << endl;
    cout << " All the commands are ignored in this section except for !stop_chat " << endl;
    cout << " Send a message to " <<  peer_username << " \n > " <<  endl;
    return 1;
}

/**
 * @brief Hanler of the command written by the user
 * 
 * @param userInput 
 * @return return -1 in case of error, 1 if no answer from the server is needed, 2 if an answer from the server is needed
 */
int commandHandler(string userInput){
    int ret;
    // Data structure which represents a command message
    struct commandMSG cmdToSend;
    cmdToSend.opcode = NOT_VALID_CMD;
    cmdToSend.userId = -1;
    // Data structure which represents a generic message
    struct genericMSG msgGenToSend;
    msgGenToSend.opcode = CHAT_RESPONSE;
    msgGenToSend.payload = NULL;
    msgGenToSend.length = 0;
    bool no_comm_with_srv=false;
    if(!isChatting || (isChatting==true && userInput.compare("!stop_chat")==0)) {
        /* ****************************************
        *          COMMAND SECTION
        * *****************************************/
        uint8_t commandCode = commandStringHandler(userInput);

        switch (commandCode){
        case CHAT_CMD:
            ret = chat(&cmdToSend,user_list);
            if(ret<0) {
                cout << " The user indicated is not in your user list - try to launch !users_online then try again " << endl;
                no_comm_with_srv=true;
            }
            break;

        case ONLINE_CMD:
            cmdToSend.opcode = ONLINE_CMD;
            break;
            
        case HELP_CMD:
            no_comm_with_srv = true;
            help();
            break;

        case EXIT_CMD:
            // The command is handled at the end of the while body
            cmdToSend.opcode = EXIT_CMD;
            break;
            
        case STOP_CHAT:
            cmdToSend.opcode = STOP_CHAT;
            break;
            
        case NOT_VALID_CMD:
            no_comm_with_srv = true;
            cout << "Command Not Valid" << endl;
                    /***************/
                    // TEST FOR DEBUG
                   // cout << " DBG _ in attesa di un opcode " << endl;
                   // uint8_t op;
                    //ret = recv(sock_id, (void*)&op, sizeof(uint8_t), 0); 
                    //cout << " opcode received " << (uint16_t)op << endl;
                    //goto close_all;
            break;
            
        default:
            no_comm_with_srv = true;                
            cout << "Command Not Valid" << endl;
            break;
        }  

        cout << " DBG - opcode of the command: " << (uint16_t)commandCode << endl;          
    }else {
        /* ****************************************
        *          CHAT SECTION
        * *****************************************/
        msgGenToSend.opcode = CHAT_RESPONSE;
        msgGenToSend.user_id_recipient = peer_id; //TODO: see if it's okay to add this
        log("Peer_id: " + to_string(peer_id) + ", id_recipient: " + to_string(msgGenToSend.user_id_recipient));
        msgGenToSend.length = userInput.size()+1; //+1 for the null terminator
        msgGenToSend.payload = (unsigned char*)malloc(msgGenToSend.length);
        if(!msgGenToSend.payload) {
            error = true;
            errorHandler(MALLOC_ERR);
            return -1;
            /*goto close_all; TODO: creare funzione di pulizia chiamabile ovunque*/
        }
        strncpy((char*)msgGenToSend.payload, userInput.c_str(), msgGenToSend.length);  
        
    }
     
    if(no_comm_with_srv)
        return 1;
    /* ********************************
    *  COMMUNICATIONS WITH SERVER 
    * ********************************/
    if(isChatting && cmdToSend.opcode!=STOP_CHAT) {
        cout << " DBG - Sending message <" << msgGenToSend.payload << "> of length <" << msgGenToSend.length << " >" << endl;
        ret = send_message(sock_id, &msgGenToSend);
        if(ret!=0){
            commandMSG stopAll;
            stopAll.opcode = STOP_CHAT;
            // I sent to the server a message to close the coms, then I close the application
            send_command_to_server(sock_id, &stopAll);
            error = true;
            errorHandler(SEND_ERR);
            return -1;
        }
        cout << " DBG -  Message sent " << endl;
        return 1;
    }
    else {
        // Send the command message to the server
        cout << " DBG - I have to sent a command message to the server ... " << endl;
        ret = send_command_to_server(sock_id, &cmdToSend);
        if(ret!=0){
            error = true;
            errorHandler(SEND_ERR);
            return -1;
        }
        cout << " DBG - Command to server sent" << endl;
    }
    return 2;
}

/**
 * @brief Handler of the messages received from the server
 * 
 * @param sock_id 
 * @return return -1 in case of error, 0 otherwise
 */
int arriveHandler(int sock_id){
 /* ****************************************
*      RECEIVE FROM THE SERVER SECTION
 * *****************************************/
    uint8_t op;
    int counterpart_id;
    int ret;
    cout << " DBG - recived something" << endl;
    // I read the first byte to understand which type of message the server is sending to me
    ret = recv(sock_id, (void*)&op, sizeof(uint8_t), 0);  
    if(ret <= 0){
        error = true;
        perror("recv on arriving something return negative value");
        errorHandler(REC_ERR);
        return -1;
    }
    /* ****************************************************************
    * Action to perform considering the things sent from the server
    * ****************************************************************/
    switch (op){
    case ONLINE_CMD:{
        cout << " DBG - Online users command handling" << endl;
        ret = retrieveOnlineUsers(sock_id, user_list);
        if(ret == 0){
            cout << " ** No users are online ** " << endl;
            }
        else if (ret==-1){
            error = true;
            errorHandler(GEN_ERR);
            
            return -1;
        }
        else if(print_list_users(user_list)!=0){
            error = true;
            errorHandler(GEN_ERR);
            return -1;
        }
        break;
    }
    case CHAT_POS:
    {
        // The server says that the client that I want to contact is available
        ret = recv(sock_id, (void*)&counterpart_id, sizeof(int), 0);  
        if(ret < 0) {
            error = true;
            errorHandler(REC_ERR);
            return -1;
        }
        if(peer_username.empty()){
            cout << " DBG - Peer username is empty " << endl;
            error = true;
            errorHandler(GEN_ERR);
            return -1;
        }
                    
        if(peer_id!=counterpart_id) {
            cout << " Server internal error: the user id requested and the one available does not match" << endl;
            break;
        }

        isChatting = true;

        cout << " ******************************** " << endl;
        cout << "               CHAT               " << endl;
        cout << " All the commands are ignored in this section except for !stop_chat " << endl;
        cout << " Send a message to " <<  peer_username << endl;
    }  
    break;
    case CHAT_NEG:
        cout << " The user has refused the request " << endl;
        break;

    case CHAT_RESPONSE:
    {
        string message;
        ret = receive_message(sock_id, message);
        if(ret!=0) {
            error = true;
            perror("chat response");
            errorHandler(REC_ERR);
            return -1;
        }

        if(peer_username.empty()){
            error = true;
            errorHandler(GEN_ERR);
            return -1;
        }
        cout << " " << peer_username << " -> " << message << endl;
    }
    break;
    case CHAT_CMD:
        ret = chatRequestHandler(sock_id);
        if(ret<=0) {
            error = true;
            perror("chat command");
            errorHandler(REC_ERR);
            return -1;
        }
    break;
    default:{
        error = true;
        cout << " DBG - opcode: " << (uint16_t)op << endl;
        errorHandler(SRV_INTERNAL_ERR);
        return -1;
    }
    break;
    }
    return 1;
}

int main(int argc, char* argv[])
{     

    string userInput;
    fd_set fdlist;
    int n_input;
    uint8_t op;
    int len;                                // size message
    int size;                               // server response size
    int ret;                                // var to store function return value
    uint16_t sizeMsgServer;                 // size msg server on the net
    uint8_t commandCode = NOT_VALID_CMD;    // variable that will contain the opcode od the last commande issued by the user
    bool need_server_answer = false;         // true if no communications with server are needed for a specific command

    // Data structure which represents a generic message
    struct genericMSG msgGenToSend;
    msgGenToSend.opcode = CHAT_RESPONSE;
    msgGenToSend.payload = NULL;
    msgGenToSend.length = 0;
    // Data structure which represents a command message
    struct commandMSG cmdToSend;
    cmdToSend.opcode = NOT_VALID_CMD;
    cmdToSend.userId = -1;
    // net structure and info
    struct sockaddr_in srv_addr;
    const char* srv_ip = "127.0.0.1";
    const int srv_port = 4242;  
    // Socket creation
    sock_id = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_id<0){
        error = true;
        errorHandler(CONN_ERR);
        goto close_all;
    }
    // Initialization for server address
    if(!memset(&srv_addr, 0, sizeof(srv_addr))){
        error = true;
        errorHandler(GEN_ERR); 
        goto close_all;
    }
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    ret = inet_pton(AF_INET, srv_ip, &srv_addr.sin_addr);
    if(ret<=0){
        error = true;
        errorHandler(CONN_ERR);
        goto close_all;
    }
    // Socket connection
    ret = connect(sock_id, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if(ret < 0){
        error = true;
        errorHandler(CONN_ERR);
        goto close_all;
    }

    // Welcome page
    welcome();

    // Authentication phase
    ret = authentication(sock_id);
    if(ret<0) {
        error = true;
        errorHandler(AUTHENTICATION_ERR);
        goto close_all;
    }
    cout << " --- AUTHENTICATION DONE --- \n > " << endl;

    // Every REQUEST_CONTROL_TIME seconds a signal is issued to control if the server has sent
    // a chat request originated from another clientS 
    // signal(SIGALRM, signal_handler);
    // alarm(REQUEST_CONTROL_TIME);
    
    printf(" ciao ");
    while(true) {
        // fdlist must be initialized after each use of the select
        FD_ZERO(&fdlist);
        FD_SET(fileno(stdin), &fdlist);
        FD_SET(sock_id, &fdlist);
        
        // cout << " IN WHILE " << endl;
        // cout << endl;
    
        printf(" > ");
        //cin >> userInput;

        int howManyDescr = 0;
        //cout << " stdin e sock: " << fileno(stdin) << " " << sock_id << endl;
        int max_descr = (fileno(stdin)>=sock_id)?fileno(stdin):sock_id;
        max_descr++;

        //cout << " numero max descr" << max_descr << endl;
        howManyDescr = select(max_descr, &fdlist, NULL, NULL, NULL);
        
        switch(howManyDescr){
        case 0:
            printf("SELECT RETURN 0\n");
            break;
        case -1:
            perror("select");
            break;
        default:
           // cout << " Descrittori pronti " << howManyDescr << endl;
            //need_server_answer = false;

            if (FD_ISSET(fileno(stdin), &fdlist)!=0) {
                // The output must be read even if need_server_answer is false
                cin >> userInput; // command from terminal arrived
                if(!need_server_answer){
                    ret = commandHandler(userInput);
                    if(ret<0){
                        error = true;
                        perror("cin");
                        errorHandler(GEN_ERR);
                        goto close_all;
                    }
                }
                if(ret==2)
                    need_server_answer=true;
                
            }
            if (FD_ISSET(sock_id, &fdlist)!=0) {
                // Something arrived on the socket  
                ret = arriveHandler(sock_id);
                if(ret<0){
                    error = true;
                    perror("recv");
                    errorHandler(GEN_ERR);
                    goto close_all;
                }
                if(ret!=2)
                   need_server_answer=false;
            } 
        } 
    }       
        
        /* An attacker knowing this can try to write CHAT_STARTED but due
         * to the fact that there is a control on isChatting (s)he is not able
         * to enter in the following if*/
       /* if(userInput.compare("CHAT_STARTED")==0 && isChatting){
            cout << " ******************************** " << endl;
            cout << "               CHAT               " << endl;
            cout << " All the commands are ignored in this section except for !stop_chat " << endl;
            cout << " Send a message to " <<  peer_username << endl;
            printf(" > ");
            cin >> userInput;
        }*/
    //cout << endl;
    //cout << userInput << endl;
       
close_all:
    if(msgGenToSend.payload)
        free(msgGenToSend.payload);

    free(server_cert);
    free(session_key_clientToServer);

    free_list_users(user_list);
    close(sock_id);
    
    if(error) {
        cout << " Forced secure termination " << endl;
        exit(-1);
    }
    else {
        cout << "\n Bye Bye" << endl;
        return 0;
    }  
}