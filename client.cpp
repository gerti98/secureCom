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
uint32_t session_key_clientToServer_len = 0;

/* Session key between client and client*/
unsigned char* session_key_clientToClient = NULL;
uint32_t session_key_clientToClient_len = 0;

/* Peer Public Key*/
unsigned char* peer_pub_key = NULL;

/* Server certificate */
unsigned char* server_cert = NULL;

// Counter for freshness
uint32_t receive_counter=0;
uint32_t send_counter=0;

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
//int retrieveOnlineUsers(int sock_id, user*& user_list)

/**
 * @brief The function receives from the server the list of the user and it store it
 * 
 * @param plaintext received message decrypted
 * @return The number of online users, -1 if error, 0 if no user in the list
 */
int retrieveOnlineUsers(unsigned char* plaintext)
{
    if(user_list!=NULL)
        free_list_users(user_list);
    uint32_t howMany;
    int ret;
    uint32_t bytes_read = 5; // Because I have already read the opcode and the seq number
    //int ret = recv(sock_id, (void*)&howMany, sizeof(int), 0);  
    memcpy(&howMany, plaintext+bytes_read, sizeof(uint32_t));
    bytes_read += sizeof(uint32_t);
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

        //ret = recv(sock_id, (void*)&(tmp->userId), sizeof(int), 0);  
        memcpy(&(tmp->userId), plaintext+bytes_read, sizeof(int));
        bytes_read += sizeof(int);

        tmp->userId = ntohl(tmp->userId);
        cout << " DBG - User id: " << tmp->userId << endl;
        if(ret <= 0) {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }

       // ret = recv(sock_id, (void*)&username_size, sizeof(int), 0);  
       /* if(ret <= 0) {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }*/
        memcpy(&username_size, plaintext+bytes_read, sizeof(int));
        bytes_read += sizeof(int);

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
        
        /*ret = recv(sock_id, (void*)(tmp->username), username_size, 0);  
        if(ret <= 0) {   
            free(tmp->username);
            free(tmp);
            free_list_users(user_list);
            return -1;
        }*/
        memcpy(tmp->username, plaintext+bytes_read, username_size);
        bytes_read += username_size;
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
 * @brief Receive in a secure way the messages sent by the server, decipher it and return the plaintext in the correspodent parameter. It
 * also control the sequence number
 * 
 * @param socket socket id
 * @param plaintext plaintext obtained by the decryption of the ciphertext
 * @return int plaintext length or -1 if error
 */
int recv_secure(int socket, unsigned char** plaintext)
{
    cout << " DBG - SECURE RECEIVE " << endl;
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT; 
    //cout << " DBG - header_len: " << header_len << endl;
    uint32_t ct_len;
    unsigned char* ciphertext = NULL;
    uint32_t pt_len;
    int ret;
 
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
    pt_len = auth_enc_decrypt(ciphertext, ct_len, aad, sizeof(uint32_t), session_key_clientToServer, tag, iv, plaintext);
    if(pt_len == 0 || pt_len!=ct_len){
        cerr << " Error during decryption " << endl;
        free(ciphertext);
        free(*plaintext);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }
    cout << " ciphertext is: " << endl;
    BIO_dump_fp(stdout, (const char*)ciphertext, ct_len);
    cout << " plaintext is " << endl;
    BIO_dump_fp(stdout, (const char*)*plaintext, pt_len);
    free(ciphertext);
    free(header);
    free(tag);
    free(iv);

    // check seq number
    uint32_t sequece_number = ntohl(*(uint32_t*) (*plaintext));
    cout << " received sequence number " << sequece_number  << " aka " << *(uint32_t*) (*plaintext) << endl;
    cout << " Expected sequence number " << receive_counter << endl;
    if(sequece_number<receive_counter){
        cerr << " Error: wrong seq number " << endl;
        free(plaintext);
        return -1;
    }
    receive_counter=sequece_number+1;

    return pt_len;
}

/**
 * @brief Perform an authenticated encryption and then a send operation - add also the sequence number at the head of the plaintext
 * 
 * @param comm_socket_id socket id
 * @param pt buffer to encrypt and send
 * @param pt_len len of the buffer
 * @return 0 in case of error, 1 otherwise
 */
int send_secure(int comm_socket_id, uchar* pt, int pt_len){
    int ret;
    uchar *tag, *iv, *ct, *aad;

    uint aad_len;
    log("Plaintext to send:");
    BIO_dump_fp(stdout, (const char*)pt, pt_len);
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT;

    // adding sequence number
    uint32_t counter_n=htonl(send_counter);
    cout <<" adding sequrnce number " << counter_n<<endl;
    uchar* pt_seq = (uchar*)malloc(pt_len+sizeof(uint32_t));
    memcpy(pt_seq , &counter_n, sizeof(uint32_t));
    memcpy(pt_seq+ sizeof(uint32_t), pt, pt_len);
    pt=pt_seq;
    pt_len+=sizeof(uint32_t);
    log("Plaintext to send (with seq):");
    BIO_dump_fp(stdout, (const char*)pt, pt_len);

    int aad_ct_len_net = htonl(pt_len); //Since we use GCM ciphertext == plaintext
    int ct_len = auth_enc_encrypt(pt, pt_len, (uchar*)&aad_ct_len_net, sizeof(uint), session_key_clientToServer, &tag, &iv, &ct);
    if(ct_len == 0){
        log("auth_enc_encrypt failed");
        return 0;
    }
    log("ct_len: " + to_string(ct_len)); 
    uint msg_to_send_len = ct_len + header_len, bytes_copied = 0;
    uchar* msg_to_send = (uchar*)malloc(msg_to_send_len);
    if(!msg_to_send){
        errorHandler(MALLOC_ERR);
        return 0;
    }

    cout << aad_ct_len_net << " -> " << ntohl(aad_ct_len_net) << endl;
    memcpy(msg_to_send + bytes_copied, &aad_ct_len_net, sizeof(uint));
    bytes_copied += sizeof(uint);
    memcpy(msg_to_send + bytes_copied, iv, IV_DEFAULT);
    bytes_copied += IV_DEFAULT;
    memcpy(msg_to_send + bytes_copied, tag, TAG_DEFAULT);
    bytes_copied += TAG_DEFAULT;
    memcpy(msg_to_send + bytes_copied, ct, ct_len);
    bytes_copied += sizeof(uint);

    log("Msg (authenticated and encrypted) to send, (copied " + to_string(bytes_copied) + " of " + to_string(msg_to_send_len) + "):");
    BIO_dump_fp(stdout, (const char*)msg_to_send, msg_to_send_len);

    //-----------------------------------------------------------
    // Controllo encr/decr
    unsigned char* pt_test = NULL;
    int pt_len_test = auth_enc_decrypt(ct, ct_len, (uchar*)&aad_ct_len_net, sizeof(uint32_t), session_key_clientToServer, tag, iv, &pt_test);
    if(pt_len_test == 0){
        log("auth_enc_decrypt failed");
        return 0;
    }
    cout << " plaintext " << endl;
    BIO_dump_fp(stdout, (const char*)pt_test, pt_len_test);
    safe_free(pt, pt_len);
    //------------------------------------------------------
    ret = send(comm_socket_id, msg_to_send, msg_to_send_len, 0);
    if(ret <= 0 || ret != msg_to_send_len){
        errorHandler(SEND_ERR);
        safe_free(msg_to_send, msg_to_send_len);
        return 0;
    }
    send_counter++;
    cout << " DBG - message sent " << endl;
    safe_free(msg_to_send, msg_to_send_len);
    return 1;
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
    unsigned char* pt = NULL;
    uint32_t pt_len = (cmdToSend->opcode==CHAT_CMD)? sizeof(uint8_t)+sizeof(uint32_t) : sizeof(uint8_t);

    pt = (unsigned char*)malloc(pt_len);
    if(!pt)
        return -1;

    /*int ret = send(sock_id,(void*)&cmdToSend->opcode, sizeof(uint8_t), 0);
    if(ret < 0 || ret!=sizeof(uint8_t))
        return -1;
      */

    memcpy(pt, &(cmdToSend->opcode), sizeof(uint8_t));

    if(cmdToSend->opcode==CHAT_CMD) {
        net_id = htonl(cmdToSend->userId);
        /*ret = send(sock_id,(void*)&net_id, sizeof(uint32_t), 0);
        if(ret < 0 || ret!=sizeof(uint32_t))
            return -1;*/
        memcpy(pt+sizeof(uint8_t), &net_id, sizeof(uint32_t));
    }

    int ret = send_secure(sock_id, pt, pt_len);
    if(ret==0){
        safe_free(pt, pt_len);
        return -1;
    }
    safe_free(pt, pt_len);
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
int receive_message(int sock_id, string& msg) // TO DO IN A SECURE WAY
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
 * @brief Called after authentication it is in charge of receving the user id of the logged user
 * 
 * @param socket 
 * @return int -1 in case of error, 0 otherwise
 */
int retrieve_my_userID(int socket)
{
    cout << " DBG - Retrieving user id " << endl;
    unsigned char* plaintext = NULL;
    int pt_len = recv_secure(sock_id, &plaintext);
    if(pt_len==-1)
        return -1;

    // check opcode
    uint8_t opcode_rec;
    memcpy(&opcode_rec, plaintext+4, sizeof(uint8_t));
    cout << " opcode received is " << (uint16_t)opcode_rec << endl;
    if(opcode_rec!=USRID){
        cerr << " Error: wrong opcode " << endl;
        free(plaintext);
        return -1;
    }

    int loggedUser_id_net;
    //BIO_dump_fp(stdout, (const char*)&loggedUser_id_net, sizeof(uint32_t));
    memcpy(&loggedUser_id_net, plaintext+sizeof(uint32_t)+1, sizeof(uint32_t));
    //BIO_dump_fp(stdout, (const char*)&loggedUser_id_net, sizeof(uint32_t));
    
    loggedUser_id = ntohl(loggedUser_id_net);
    //BIO_dump_fp(stdout, (const char*)&loggedUser_id, sizeof(uint32_t));
    cout << " I'm the user with ID " << loggedUser_id  << " aka " << loggedUser_id_net << endl;  
    return 0;
}


/**
 * @brief It performs the authentication procedure with the server or the client depending by the passed parameter
 * 
 * @param sock_id  socket id
 * @param ver AUTH_CLNT_SRV (if authentication between client and server) or AUTH_CLNT_CLNT (if authentication between client and client)
 * @return -1 if error, 0 otherwise
 */
int authentication(int sock_id, uint8_t ver)
{
    // If the authentication is done with another client with the word server is indicated the other client
    if(ver!=AUTH_CLNT_CLNT && ver!=AUTH_CLNT_SRV)
        return -1;
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

    unsigned char* msg2_pt = NULL;
    uint32_t msg2_pt_len = 0;

    int dh_pub_srv_key_size;
    unsigned char* dh_server_pubkey = NULL;

    uint32_t len_signature;
    uint32_t len_signed_msg;
    unsigned char* signed_msg = NULL;
    unsigned char* signature = NULL;

    uint32_t cert_length;
    unsigned char* server_cert = NULL;  

    // Acquire the username from stdin
    if(ver==AUTH_CLNT_SRV){
        do{
            if(tooBig)
                cout << " The username inserted is too big! " << endl;
            cout << " Who are you? " << endl;
            cout << " > ";
            cin >> loggedUser;
            if(loggedUser.size()+1>MAX_USERNAME_SIZE)
                tooBig = true;
        }while(tooBig);
    }

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
    if(ver==AUTH_CLNT_SRV){
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
    }
    // Composition of the message: OPCODE, R, USERNAME_SIZE, USERNAME
    cout << " DBG - Composition of the message " << endl;
    size_to_allocate = (ver==AUTH_CLNT_SRV) ? (NONCE_SIZE+sizeof(uint32_t)+usernameSize) : (sizeof(uint8_t) + NONCE_SIZE + sizeof(int));
    msg_auth_1 = (unsigned char*)malloc(size_to_allocate);
    if(!msg_auth_1){
        free(name);
        free(nonce);
        return -1;
    }

    if(ver==AUTH_CLNT_SRV){
        memcpy(msg_auth_1, nonce, NONCE_SIZE);
        msg_bytes_written = NONCE_SIZE; 
        memcpy(msg_auth_1+msg_bytes_written, &net_usernameSize, sizeof(uint32_t));
        msg_bytes_written += sizeof(uint32_t);
        memcpy(msg_auth_1+msg_bytes_written, name, usernameSize);
        msg_bytes_written += usernameSize;
    }
    else if(ver==AUTH_CLNT_CLNT){
        uint8_t op = AUTH;
        memcpy(msg_auth_1, (void*)&op, sizeof(uint8_t));
        msg_bytes_written = sizeof(uint8_t);
        memcpy(msg_auth_1+msg_bytes_written, nonce, NONCE_SIZE);
        msg_bytes_written += NONCE_SIZE;
        memcpy(msg_auth_1+msg_bytes_written, (void*)&peer_id, sizeof(int));
        msg_bytes_written += sizeof(int);
    }

    cout << " DBG - M1: " << endl;
    BIO_dump_fp(stdout, (const char*)msg_auth_1, msg_bytes_written);

    // Send the message to the server
    cout << " DBG - Sending M1 to server " << endl;
    if(ver==AUTH_CLNT_SRV){
        ret = send(sock_id, (void*)msg_auth_1, msg_bytes_written, 0);
        if(ret<=0 || ret != msg_bytes_written){
            free(msg_auth_1);
            free(name);
            free(nonce);
            return -1;
        }
        // free message and unnecessary stuff
        free(name);
    }
    else if(ver==AUTH_CLNT_CLNT){
        send_secure(sock_id, msg_auth_1, size_to_allocate);
    }
    safe_free(msg_auth_1, size_to_allocate);

    /*************************************************************
     * M2 - Wait for message from the server
     *************************************************************/
    cout << " DBG - Wait for M2" << endl;
    // wait for nonce
    if(ver==AUTH_CLNT_CLNT){
        msg2_pt_len = recv_secure(sock_id, &msg2_pt);
        if(msg2_pt_len==-1){
            return -1;
        }
    }
    uint32_t read_from_msg2 = sizeof(uint32_t); // seq number already read in recv_secure
    
    server_nonce = (unsigned char*)malloc(NONCE_SIZE);
    if(!server_nonce){
        free(nonce);
        return -1;
    }

    if(ver==AUTH_CLNT_SRV){
        ret = recv(sock_id, (void*)server_nonce, NONCE_SIZE, 0);  
        if(ret <= 0){
            free(server_nonce);
            free(nonce);
            return -1;
        }
    }
    else if(ver==AUTH_CLNT_CLNT){
        uint8_t op_tmp;
        memcpy(&op_tmp, msg2_pt+read_from_msg2, sizeof(uint8_t));
        read_from_msg2 += sizeof(uint8_t);
        if(op_tmp!=AUTH){
            free(server_nonce);
            free(nonce);
            return -1;
        }
        memcpy(server_nonce, msg2_pt + read_from_msg2, NONCE_SIZE);
        read_from_msg2 += NONCE_SIZE;
    }
    cout << " DBG - R2 received: " << endl;
    BIO_dump_fp(stdout, (const char*)&server_nonce, NONCE_SIZE);

    // Read the length of the DH server pub key
    cout << " DBG - Read length of DH server pub key " << endl;
    if(ver==AUTH_CLNT_SRV){
        ret = recv(sock_id, (void*)&dh_pub_srv_key_size, sizeof(int), 0);  
        if(ret <= 0){
            free(server_nonce);
            free(nonce);
            return -1;
        }
    }
    else if(ver==AUTH_CLNT_CLNT){
        memcpy(&dh_pub_srv_key_size, msg2_pt+read_from_msg2, sizeof(int));
        read_from_msg2 += sizeof(int);
    }
    dh_pub_srv_key_size = ntohl(dh_pub_srv_key_size);

    // Read DH server pub key
    cout << " DBG - Read server pubkey for "<< dh_pub_srv_key_size<<" bytes"<< endl;
    dh_server_pubkey = (unsigned char*)malloc(dh_pub_srv_key_size);
    if(!dh_server_pubkey){
        free(server_nonce);
        free(nonce);
    }

    if(ver==AUTH_CLNT_SRV){
        ret = recv(sock_id, (void*)dh_server_pubkey, dh_pub_srv_key_size, 0);  
        if(ret <= 0 || ret != dh_pub_srv_key_size){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            return -1;
        }
    }
    else if(ver==AUTH_CLNT_CLNT){
        memcpy(dh_server_pubkey, msg2_pt+read_from_msg2, dh_pub_srv_key_size);
        read_from_msg2 += dh_pub_srv_key_size;
    }

    cout << " DBG - DHpubk_S received: " << endl;
    BIO_dump_fp(stdout, (const char*)&dh_server_pubkey, dh_pub_srv_key_size);


    // Read signature length
    cout << " DBG - Read signature length " << endl;
    if(ver==AUTH_CLNT_SRV){
        ret = recv(sock_id, (void*)&len_signature, sizeof(uint32_t), 0);  
        if(ret <= 0 || ret!=sizeof(uint32_t)){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            return -1;
        }
    }
    else if(ver==AUTH_CLNT_CLNT){
        memcpy(&len_signature, msg2_pt+read_from_msg2, sizeof(uint32_t));
        read_from_msg2 += sizeof(uint32_t);
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

    if(ver==AUTH_CLNT_SRV){
        ret = recv(sock_id, (void*)signature, len_signature, 0);  
        if(ret <= 0 || ret!=len_signature){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signature);
            return -1;
        }
    }
    else if(ver==AUTH_CLNT_CLNT){
        memcpy(signature, msg2_pt+read_from_msg2, len_signature);
        read_from_msg2 += len_signature;
    }
    
    // Read certificate length
    if(ver==AUTH_CLNT_SRV){
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

    if(ver==AUTH_CLNT_SRV){
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
    }
    else if(ver==AUTH_CLNT_CLNT){
        if(!peer_pub_key){
            cerr << " Peer public key not present " << endl; 
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signed_msg);
            free(signature);
            return -1;
        }
        ret = verify_sign_pubkey(signature, len_signature, signed_msg, len_signed_msg, peer_pub_key, PUBKEY_DEFAULT);
        if(ret==0){
            cerr << " Verification of the signature of the peer failed " << endl;
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            free(signed_msg);
            free(signature);
            return -1;
        }
    }
    free(signature);
    free(signed_msg);
    free(nonce);
    

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
    if(ver==AUTH_CLNT_CLNT)
        msglen = msglen + sizeof(uint8_t) + sizeof(int); // additional size for the opcode and peer id
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
    if(ver==AUTH_CLNT_CLNT){
        uint8_t op_tmp = AUTH;
        memcpy(msg_to_send_M3+msg_bytes_written, &op_tmp, sizeof(uint8_t));
        msg_bytes_written += sizeof(uint8_t);
        memcpy(msg_to_send_M3+msg_bytes_written, &peer_id, sizeof(int));
        msg_bytes_written += sizeof(int);
    }
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
    if(ver==AUTH_CLNT_SRV){
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
    }
    else if(ver==AUTH_CLNT_CLNT){
        ret = send_secure(sock_id, msg_to_send_M3, msglen);
        if(ret==0){
            free(dh_server_pubkey);
            free(client_signature);
            free(msg_to_send_M3);
            free(eph_dh_privKey);
            free(eph_dh_pubKey);
            return -1;
        }
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
    session_key_clientToClient = NULL;
    uint32_t keylen;
    if(ver==AUTH_CLNT_SRV)
        keylen = default_digest(secret, secret_len, &session_key_clientToServer);
    else if(ver==AUTH_CLNT_CLNT)
        keylen = default_digest(secret, secret_len, &session_key_clientToClient);

    if(keylen==0){
        free(server_cert);
        safe_free(session_key_clientToServer, session_key_clientToServer_len);
        safe_free(session_key_clientToClient, session_key_clientToClient_len);
        safe_free(secret, secret_len);
        return -1;
    }
    
    if(ver==AUTH_CLNT_SRV)
        session_key_clientToServer_len =  keylen;
    else if(ver==AUTH_CLNT_CLNT)
        session_key_clientToClient_len = keylen;

    safe_free(secret, secret_len);
    cout << "DBG - Session key generated!" << endl;
    if(ver==AUTH_CLNT_CLNT)
        BIO_dump_fp(stdout, (const char*)session_key_clientToClient, keylen);
    else if(ver==AUTH_CLNT_SRV)
        BIO_dump_fp(stdout, (const char*)session_key_clientToServer, keylen);
    /************************************************************
     * End of Authentication 
     ************************************************************/
    if(ver==AUTH_CLNT_SRV){
        ret = retrieve_my_userID(sock_id);
        if(ret!=0){
            cerr << " Error during the retrieving of the user id " << endl;
            return -1;
        }
    }
    // If we are arrived here the authentication is done succesfully
    return 0;
}


/**
 * @brief Handle the authentication between two client on the receiver side of the chat request
 * 
 * @param sock_id 
 * @return -1 in case of error, 0 otherwise
 */
int authentication_receiver(int sock_id)
{
    int ret;
    uint8_t op_rec;
    uint32_t id_dest;
    /*************************************************************
     * M1 - R1
     *************************************************************/
    uchar* R1 = (uchar*)malloc(NONCE_SIZE);
    if(!R1){
        errorHandler(MALLOC_ERR);
        return -1;
    }

    unsigned char* pt_M1 = NULL;
    uint32_t pt_M1_len = 0;
    pt_M1_len = recv_secure(sock_id, &pt_M1);
    if(pt_M1_len<=0){
        cerr << " Error during M1 reception in authentication_receiver " << endl;
        safe_free(R1, NONCE_SIZE);
        return -1;
    }
    log("M1 auth received: ");
    BIO_dump_fp(stdout, (const char*)pt_M1, NONCE_SIZE);

    uint32_t bytes_read = sizeof(uint32_t); // Because sequence number already read in recv_secure

    memcpy(&op_rec, pt_M1+bytes_read, sizeof(uint8_t));
    bytes_read += sizeof(uint8_t);
    if(op_rec!=AUTH){
        cerr << " Wrong opcode received " << endl;
        free(R1);
        safe_free(pt_M1, pt_M1_len);
    }
    memcpy(&id_dest, pt_M1+bytes_read, sizeof(uint32_t));
    bytes_read += sizeof(uint32_t);
    if(id_dest!=loggedUser_id){
        cerr << " Wrong destination id " << endl;
        free(R1);
        safe_free(pt_M1, pt_M1_len);
    }
    memcpy(R1, pt_M1+bytes_read, NONCE_SIZE);
    bytes_read+=NONCE_SIZE;

    safe_free(pt_M1, pt_M1_len);

    /*************************************************************
     * M2 - Send R2,pubkey_eph,signature
     *************************************************************/
    uchar* R2 = (uchar*)malloc(NONCE_SIZE);
    if(!R2){
        errorHandler(MALLOC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
    }

    //Generate pair of ephermeral DH keys
    void* eph_privkey_s;
    uchar* eph_pubkey_s;
    uint eph_pubkey_s_len;
    ret = eph_key_generate(&eph_privkey_s, &eph_pubkey_s, &eph_pubkey_s_len);
    if(ret != 1){
        log("Error on EPH_KEY_GENERATE");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }
    log("M2 auth (1) pubkey: ");
    BIO_dump_fp(stdout, (const char*)eph_pubkey_s, eph_pubkey_s_len);

    //Generate nuance R2
    ret = random_generate(NONCE_SIZE, R2);
    if(ret != 1){
        log("Error on random_generate");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }

    log("auth (2) R2: ");
    BIO_dump_fp(stdout, (const char*)R2, NONCE_SIZE);


    uint32_t M2_to_sign_length = (NONCE_SIZE*2) + eph_pubkey_s_len;

    uint32_t M2_signed_length;
    uchar* M2_signed;
    uchar* M2_to_sign = (uchar*)malloc(M2_to_sign_length);
    if(!M2_to_sign){
        log("Error on M2_to_sign");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }

    memcpy(M2_to_sign, R1, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + NONCE_SIZE), R2, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + (2*NONCE_SIZE)), eph_pubkey_s, eph_pubkey_s_len);
    log("auth (4) M2_to_sign: ");
    BIO_dump_fp(stdout, (const char*)M2_to_sign, M2_to_sign_length);

    string privkey_file_path = "clients_data/"+loggedUser+"/"+loggedUser+"_privkey.pem";
    FILE* privKey_file = fopen(privkey_file_path.c_str(), "rb");
    if(!privKey_file){
        cerr<<"error unable to read privkey file"<<endl;
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        safe_free(M2_to_sign, M2_to_sign_length);
        return -1;
    }

    
    ret = sign_document(M2_to_sign, M2_to_sign_length, privKey_file, &M2_signed, &M2_signed_length);
    if(ret != 1){
        log("Error on signing part on M2");
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        fclose(privKey_file);
        return -1;
    }
    
    fclose(privKey_file);

    //Send M2 part by part
    uint M2_size = sizeof(uint8_t) + sizeof(int) + NONCE_SIZE + sizeof(int) + eph_pubkey_s_len + sizeof(int) + M2_signed_length;
    uint offset = 0;
    uchar* M2 = (uchar*)malloc(M2_size);
    uint eph_pubkey_s_len_net = htonl(eph_pubkey_s_len);
    uint M2_signed_length_net = htonl(M2_signed_length);
   
    log("Copying");
    uint8_t opcode = AUTH;
    memcpy(M2+offset, &opcode, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    memcpy(M2+offset, &peer_id, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy((void*)(M2 + offset), R2, NONCE_SIZE);
    offset += NONCE_SIZE;
    log(to_string(offset));
    memcpy((void*)(M2 + offset), &eph_pubkey_s_len_net, sizeof(uint));
    offset += sizeof(uint);
    log(to_string(offset));
    memcpy((void*)(M2 + offset), eph_pubkey_s, eph_pubkey_s_len);
    offset += eph_pubkey_s_len;
    log(to_string(offset));
    memcpy((void*)(M2 + offset), &M2_signed_length_net ,sizeof(uint));
    offset += sizeof(uint);
    log(to_string(offset));
    memcpy((void*)(M2 + offset), M2_signed,M2_signed_length);
    offset += M2_signed_length;
    log(to_string(offset));

    log("M2 size: " + to_string(M2_size));

    ret = send_secure(sock_id, M2, M2_size);
    if(ret==0){
        cerr << " Error during send_secure in sending M2 " << endl;
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }
    log("M2 sent");
    BIO_dump_fp(stdout, (const char*)M2, offset);
        
    safe_free(M2, M2_size);
    safe_free(M2_to_sign, M2_to_sign_length);
    safe_free(R1, NONCE_SIZE);
    safe_free(eph_pubkey_s, eph_pubkey_s_len);
    

    /*************************************************************
     * M3 - client_pubkey and signing of pubkey and R2
     *************************************************************/
    uint32_t eph_pubkey_c_len;
    unsigned char* msg3 = NULL;
    uint32_t msg3_len = 0;
    msg3_len = recv_secure(sock_id, &msg3);
    if(msg3_len <= 0){
        cerr << " Error in recv_secure during M3 reception " << endl;
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        return -1;
    }

    bytes_read = 1; // seq number already read in recv secure

    memcpy(&op_rec, msg3+bytes_read, sizeof(uint8_t));
    bytes_read += sizeof(uint8_t);
    if(op_rec!=AUTH){
        cerr << " Wrong opcode received " << endl;
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
    }
    memcpy(&id_dest, msg3+bytes_read, sizeof(uint32_t));
    bytes_read += sizeof(uint32_t);
    if(id_dest!=loggedUser_id){
        cerr << " Wrong destination id " << endl;
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
    }
    memcpy(&eph_pubkey_c_len, msg3+bytes_read, sizeof(uint32_t));
    bytes_read+=sizeof(uint32_t);
    eph_pubkey_c_len = ntohl(eph_pubkey_c_len);
    log("M3 auth (1) pubkey_c_len: "+ to_string(eph_pubkey_c_len));

    uchar* eph_pubkey_c = (uchar*)malloc(eph_pubkey_c_len);
    if(!eph_pubkey_c ){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
        return -1;
    }

    memcpy(eph_pubkey_c, msg3+bytes_read, eph_pubkey_c_len);
    bytes_read += eph_pubkey_c_len;
    log("M3 auth (2) pubkey_c:");
    BIO_dump_fp(stdout, (const char*)eph_pubkey_c, eph_pubkey_c_len);

    uint32_t m3_signature_len;
    memcpy(&m3_signature_len, msg3+bytes_read, sizeof(uint32_t));
    bytes_read += sizeof(uint32_t);
    m3_signature_len = ntohl(m3_signature_len);
    log("M3 auth (3) m3_signature_len: "+ to_string(m3_signature_len));

    uchar* M3_signed = (uchar*)malloc(m3_signature_len); //TODO: control tainted
    if(!M3_signed){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        return -1;
    }

    memcpy(M3_signed, msg3+bytes_read, m3_signature_len);
    bytes_read += m3_signature_len;

    safe_free(msg3, msg3_len);

    log("auth (4) M3 signed:");
    BIO_dump_fp(stdout, (const char*)M3_signed, m3_signature_len);


    uint m3_document_size = eph_pubkey_c_len + NONCE_SIZE;
    uchar* m3_document = (uchar*)malloc(m3_document_size);
    if(!m3_document){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
    }

    memcpy(m3_document, eph_pubkey_c,eph_pubkey_c_len );
    memcpy(m3_document+eph_pubkey_c_len, R2, NONCE_SIZE);
    log("auth (5) M3, verifying sign");
    if(peer_pub_key==NULL){
        cerr << " Peer public key not present " << endl;
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
    }

    ret = verify_sign_pubkey(M3_signed, m3_signature_len, m3_document, m3_document_size, peer_pub_key, PUBKEY_DEFAULT);
    if(ret == 0){
        log("Failed sign verification on M3");
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
    }

    safe_free(R2, NONCE_SIZE);
    safe_free(M3_signed, m3_signature_len);

    uchar* shared_secret;
    uint shared_secret_len;
    log("auth (6) Creating session key");
    shared_secret_len = derive_secret(eph_privkey_s, eph_pubkey_c, eph_pubkey_c_len, &shared_secret);
    if(shared_secret_len == 0){
        log("Failed derive secret");
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free_privkey(eph_privkey_s);
        return -1;    
    }
    log("Shared Secret!");
    BIO_dump_fp(stdout, (const char*) shared_secret, shared_secret_len);

    session_key_clientToClient_len = default_digest(shared_secret, shared_secret_len, &session_key_clientToClient);
    if(session_key_clientToClient_len == 0){
        log("Failed digest computation of the secret");
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(shared_secret, shared_secret_len);
        safe_free_privkey(eph_privkey_s);
        return -1;    
    }
    log("Session key generated!");
    BIO_dump_fp(stdout, (const char*) session_key_clientToClient, session_key_clientToClient_len);
    safe_free(eph_pubkey_c, eph_pubkey_c_len);
    safe_free(shared_secret, shared_secret_len);
    safe_free_privkey(eph_privkey_s);
    
    cout << " AUTHENTICATION WITH " << peer_username << " SUCCESFULLY EXECUTED " << endl;
    return 0;
}

/**
 * @brief handle an incoming chat request
 * 
 * @param plaintext message received
 * @return 1 if everything's ok, 0 on error(s)
 */
int chatRequestHandler(unsigned char* plaintext)
{
    int ret;
    uint8_t opcode = NOT_VALID_CMD;
    uint8_t response;
    int id_cp;
    unsigned char* counterpart;
    int size_username;
    char user_resp = 'a';
    unsigned char* risp_buff = NULL;
    size_t risp_buff_size = 0;
    uint32_t bytes_read = 5; // because I have already read the opcode and the seq number
    cout << " DBG - Received a chat request " << endl;

    // Reading of the peer id
    /*ret = recv(sock_id, (void*)&id_cp, sizeof(int), 0); 
    if(ret <= 0){
        cout << " DBG - peer id not received " << endl;
        alarm(REQUEST_CONTROL_TIME);
        return 0;
    }*/
    memcpy(&id_cp, plaintext, sizeof(int));
    bytes_read += sizeof(int);
    // htonl of id_cp is done afterwards
    
    // Read username length
    /*ret = recv(sock_id, (void*)&size_username, sizeof(int), 0); 
    if(ret <= 0 || size_username==0){
        cout << " DBG - username length not received " << endl;
        alarm(REQUEST_CONTROL_TIME);
        return 0;
    }*/
    memcpy(&size_username, plaintext+bytes_read, sizeof(int));
    bytes_read += sizeof(int);

    cout << " size: " << size_username << " aka " << ntohl(size_username) << endl;
    size_username = ntohl(size_username);
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

    /*ret = recv(sock_id, (void*)counterpart, size_username, 0); 
    if(ret <= 0){
        cout << " DBG - username not received " << endl;
        alarm(REQUEST_CONTROL_TIME);
        return 0;
    }*/
    memcpy(counterpart, plaintext+bytes_read, size_username);
    bytes_read += size_username;
    cout << " cp: " << counterpart << endl;

    // Read sender pubkey
    // Public key of an old peer
    if(peer_pub_key!=NULL)
        free(peer_pub_key);
    peer_pub_key = (unsigned char*)malloc(PUBKEY_DEFAULT);
    if(!peer_pub_key)
        return 0;    
    
    memcpy(peer_pub_key, plaintext+bytes_read, PUBKEY_DEFAULT);
    bytes_read += PUBKEY_DEFAULT;    

    if(isChatting){
        cout << " DBG - Automatic response because I am chatting " << endl;
        // Automatic response
        free(counterpart);
        risp_buff_size = sizeof(uint8_t)+sizeof(int);
        risp_buff = (unsigned char*)malloc(risp_buff_size);
        if(!risp_buff){
            //alarm(REQUEST_CONTROL_TIME);
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

    risp_buff_size = sizeof(uint8_t)+sizeof(int);
    risp_buff = (unsigned char*)malloc(risp_buff_size);
    if(!risp_buff){
        alarm(REQUEST_CONTROL_TIME);
        // BUFFER OVERFLOW PROBLEM? RETURN IS ENOUGH?
        return 0;
    }
    
    memcpy((void*)risp_buff, (void*)&response, sizeof(uint8_t));
    memcpy((void*)(risp_buff+1), (void*)&id_cp, sizeof(int));

    //ret = send(sock_id, (void*)risp_buff, risp_buff_size, 0);
    ret = send_secure(sock_id, risp_buff, risp_buff_size);
    if(ret==-1){
        free(risp_buff);
        return 0;
    }
    free(risp_buff);

    // I am now chatting with the user that request to contact me
    // Clean stdin by what we have digit previously
    cin.clear();
    fflush(stdin);


    // INSERIRE AUTENTICAZIONE CLIENT-CLIENT
    ret = authentication_receiver(sock_id);
    if(ret==-1){
        cout << " Authentication with " << peer_username <<" failed " << endl;
        return 0;
    }

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
        ret = send_message(sock_id, &msgGenToSend); // TO DO IN SECURE WAY
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
    cout << " DBG - received something" << endl;

    unsigned char* plaintext = NULL;
    int pt_len = recv_secure(sock_id, &plaintext);
    if(pt_len==-1)
        return -1;

    memcpy(&op, plaintext+sizeof(uint32_t), sizeof(uint8_t));
    cout << " opcode arrived : " << op << endl;

    // I read the first byte to understand which type of message the server is sending to me
    /*ret = recv(sock_id, (void*)&op, sizeof(uint8_t), 0);  
    if(ret <= 0){
        error = true;
        perror("recv on arriving something return negative value");
        errorHandler(REC_ERR);
        return -1;
    }*/
    /* ****************************************************************
    * Action to perform considering the things sent from the server
    * ****************************************************************/
    switch (op){
    case ONLINE_CMD:{
        cout << " DBG - Online users command handling" << endl;
       // ret = retrieveOnlineUsers(sock_id, user_list);
        ret = retrieveOnlineUsers(plaintext);
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
        /*ret = recv(sock_id, (void*)&counterpart_id, sizeof(int), 0);  
        if(ret < 0) {
            error = true;
            errorHandler(REC_ERR);
            return -1;
        }*/
        memcpy(&counterpart_id, plaintext+5, sizeof(int)); // +5 because I have already read the opcode and the seq number
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

        authentication(sock_id, AUTH_CLNT_CLNT);
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
        ret = receive_message(sock_id, message); // TO DO IN A SECURE WAY
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
        //ret = chatRequestHandler(sock_id);
        ret = chatRequestHandler(plaintext);
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
    ret = authentication(sock_id, AUTH_CLNT_SRV);
    if(ret<0) {
        error = true;
        errorHandler(AUTHENTICATION_ERR);
        goto close_all;
    }
    cout << " --- AUTHENTICATION DONE --- " << endl;

    // Every REQUEST_CONTROL_TIME seconds a signal is issued to control if the server has sent
    // a chat request originated from another clientS 
    // signal(SIGALRM, signal_handler);
    // alarm(REQUEST_CONTROL_TIME);
    
    cout << " HELLO " << loggedUser << endl;

    while(true) {
        // fdlist must be initialized after each use of the select
        FD_ZERO(&fdlist);
        FD_SET(fileno(stdin), &fdlist);
        FD_SET(sock_id, &fdlist);
        
        // cout << " IN WHILE " << endl;
        // cout << endl;
    
        // printf(" > ");
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

    free(peer_pub_key);
    safe_free(session_key_clientToClient, session_key_clientToClient_len);
    free(server_cert);
    safe_free(session_key_clientToServer, session_key_clientToServer_len);

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