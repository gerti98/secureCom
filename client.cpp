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
#include <limits>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sstream>
#include "constant.h"
#include "util.h"
#include "crypto.h"


using namespace std;

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
uint32_t receive_counter_client_client = 0;
uint32_t send_counter_client_client = 0;

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
    cout << "\n*********************************************************************" << endl;
    cout << " !users_online" << endl;
    cout << "   Ask the server to return the list of the online users" << endl;
    cout << " !chat" << endl;
    cout << "   Ask the server to start a chat" << endl;
    cout << " !exit" << endl;
    cout << "   Close the application" << endl;
    cout << "*********************************************************************\n" << endl;
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
 * @return string that is the username, empty string if error
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
    if(userlist==NULL || toSend==NULL)
        return -1;
    toSend->opcode = CHAT_CMD; 
    cout << "\n******************************************************" << endl;
    cout << "Write the userID of the user that you want to contact" << endl;
    printf(" > ");
    cin >> toSend->userId;
    if(cin.fail()){
        cin.clear();
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return -1;
    }
    cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    if(toSend->userId==loggedUser_id){
        cout << " You cannot chat with yourself " << endl;
        return -1;
    }
    if(toSend->userId<0){
        cout << " Negative user id " << endl;
        return -1;
    }
    cout << "Wait for user's response and authentication ...." << endl;
    peer_id = toSend->userId;
    peer_username = getUsernameFromID(peer_id, userlist);
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
 * @param plaintext received message decrypted
 * @param pt_len length of the message decrypted
 * @return The number of online users, -1 if error, 0 if no user in the list
 */
int retrieveOnlineUsers(unsigned char* plaintext, uint32_t pt_len)
{
    if(plaintext==NULL)
        return -1;
    if(user_list!=NULL){
        free_list_users(user_list);
        user_list = NULL;
    }
    uint32_t howMany;
    int ret;
    uint32_t bytes_read = 5; // Because I have already read the opcode and the seq number
    // Read how many users
    memcpy(&howMany, plaintext+bytes_read, sizeof(uint32_t));
    bytes_read += sizeof(uint32_t);
    howMany = ntohl(howMany);
    
    if(ret <= 0)
        return -1;
    if(howMany==0)
        return 0;
    if(howMany>REGISTERED_USERS)
        return -1;

    struct user* current = NULL;
    struct user* tmp = NULL;

    for(int i = 0; i<howMany; i++) {
        int username_size;
        tmp = (struct user*)malloc(sizeof(user));
        if(!tmp) {
            errorHandler(MALLOC_ERR); 
            free_list_users(user_list);
            user_list = NULL;
            return -1;
        }

        tmp->username = NULL;
        tmp->userId = -1;
        tmp->next = NULL;
        tmp->usernameSize = 0;

        memcpy(&(tmp->userId), plaintext+bytes_read, sizeof(int));
        bytes_read += sizeof(int);

        tmp->userId = ntohl(tmp->userId);
        if(ret <= 0) {
            free(tmp);
            free_list_users(user_list);
            user_list = NULL;
            return -1;
        }

        memcpy(&username_size, plaintext+bytes_read, sizeof(int));
        bytes_read += sizeof(int);

        username_size = ntohl(username_size);
        tmp->usernameSize = username_size;
        if(username_size>MAX_USERNAME_SIZE) {
            free(tmp);
            free_list_users(user_list);
            user_list = NULL;
            return -1;
        }

        tmp->username = (unsigned char*)malloc(username_size+1);
        if(!tmp->username){
            errorHandler(MALLOC_ERR);
            free(tmp);
            free_list_users(user_list);
            user_list = NULL;
            return -1;
        }
        
        if(bytes_read+username_size>pt_len){
            cerr << " Error in reading plaintext " << endl;
            free(tmp);
            free_list_users(user_list);
            user_list = NULL;
            return -1;
        }
        memcpy(tmp->username, plaintext+bytes_read, username_size);
        bytes_read += username_size;
        tmp->username[username_size] = '\0';
   
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
        cout << " User list is NULL " << endl;
        return -1;
    }
    struct user* tmp = userlist;
    cout << endl;
    cout << "**** USER LIST **** " << endl;
    cout << "  ID \t Username" << endl;
    while(tmp!=NULL) {
        cout << "  " << tmp->userId << " \t " << tmp->username << endl;
        tmp = tmp->next;
    }
    cout << "****************** " << endl;
    cout << endl;
    return 0;
}

/**
 * @brief Retrieve the plaintext from the encrypted message
 * 
 * @param ciphertext ciphertext
 * @param ct_len ciphertext length
 * @param plaintext plaintext 
 * @return Return plaintext len or -1 in case of error
 */
int open_msg_by_client(unsigned char* ciphertext, uint32_t msgRecLen, unsigned char** plaintext)
{
    if(ciphertext==NULL)
        return -1;
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT; 
    uint32_t read = 9; // because seq number, opcode and len already read
    uint32_t ct_len;
    uint32_t pt_len;
    int ret;
 
    unsigned char* header = (unsigned char*)malloc(header_len);
    if(!header){
        cerr << " Error in malloc for header " << endl; 
        return -1;
    }

    memcpy(header, ciphertext+read, header_len);
    read += header_len;

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

    // Open header
    memcpy((void*)&ct_len, header, sizeof(uint32_t));
    ct_len = ntohl(ct_len);

    memcpy(iv, header+sizeof(uint32_t), IV_DEFAULT);
    memcpy(tag, header+sizeof(uint32_t)+IV_DEFAULT, TAG_DEFAULT);

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

    if(session_key_clientToClient==NULL){
        cerr << " Null key " << endl;
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        free(aad);
        return -1;
    }

    unsigned char* toDecrypt = (unsigned char*)malloc(ct_len);
    if(!aad){
        cerr << " Error in toDecrypt malloc " << endl;
        free(aad);
        free(ciphertext);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }

    memcpy(toDecrypt, ciphertext+read, ct_len);

    pt_len = auth_enc_decrypt(toDecrypt, ct_len, aad, sizeof(uint32_t), session_key_clientToClient, tag, iv, plaintext);
    if(pt_len == 0 || pt_len!=ct_len){
        cerr << " Error during decryption " << endl;
        free(ciphertext);
        free(*plaintext);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }
    free(ciphertext);
    free(header);
    free(tag);
    free(iv);

    // check seq number
    uint32_t sequence_number = ntohl(*(uint32_t*) (*plaintext));

    if(sequence_number<receive_counter_client_client){
        cerr << " Error: wrong seq number " << endl;
        safe_free(*plaintext,pt_len);
        return -1;
    }
    if(sequence_number==MAX_SEQ_NUM){
        cerr << " Error: maximum number of message in the session reached " << endl;
        safe_free(*plaintext,pt_len);
        return -1;
    }
    receive_counter_client_client=sequence_number+1;

    uint32_t msg_len = pt_len - sizeof(uint32_t);
    unsigned char* risp = (unsigned char*)malloc(msg_len);
    if(!risp)
        return -1;

    memcpy(risp, ((*plaintext)+sizeof(uint32_t)), msg_len);

    safe_free((*plaintext), pt_len);

    *plaintext = risp; 

    return msg_len;
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
    if(sock_id<0)
        return -1;
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT; 
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
    ret = recv(sock_id, (void*)header, header_len, 0);
    if(ret <= 0 || ret != header_len){
        cerr << " Error in header reception " << ret << endl;
        BIO_dump_fp(stdout, (const char*)header, header_len);
        free(header);
        free(tag);
        free(iv);
        return -1;
    }

    // Open header
    memcpy((void*)&ct_len, header, sizeof(uint32_t));

    memcpy(iv, header+sizeof(uint32_t), IV_DEFAULT);
    memcpy(tag, header+sizeof(uint32_t)+IV_DEFAULT, TAG_DEFAULT);

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

    // Receive ciphertext
    ct_len = ntohl(ct_len);
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

    // Decryption
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
    free(ciphertext);
    free(header);
    free(tag);
    free(iv);

    // check seq number
    uint32_t sequece_number = ntohl(*(uint32_t*) (*plaintext));
 
    if(sequece_number<receive_counter){
        cerr << " Error: wrong seq number " << endl;
        free(plaintext);
        return -1;
    }
    if(sequece_number==MAX_SEQ_NUM){
        cerr << " Error: maximum number of message in the session reached " << endl;
        safe_free(*plaintext,pt_len);
        return -1;
    }
    receive_counter=sequece_number+1;

    return pt_len;
}

/**
 * @brief Prepare the message for the client. The plaintext is safely free inside the function
 * 
 * @param plaintext 
 * @param pt_len 
 * @param msg_to_send 
 * @return The length of msg_to_send, 0 if error(s)
 */
int prepare_msg_for_client(unsigned char* pt, uint32_t pt_len, unsigned char** msg_to_send)
{
    if(pt==NULL)
        return -1;
    int ret;
    uchar *tag, *iv, *ct, *aad;
    uint aad_len;
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT;

    // adding sequence number
    uint32_t counter_n=htonl(send_counter_client_client);
    
    if(pt_len>UINT32_MAX-sizeof(uint32_t)){
        cerr << " Too big number for malloc " << endl;
        return -1;
    }
    uchar* pt_seq = (uchar*)malloc(pt_len+sizeof(uint32_t)); 
    if(!pt_seq){
        safe_free(pt, pt_len);
        return 0;
    }

    memcpy(pt_seq, &counter_n, sizeof(uint32_t));
    memcpy(pt_seq+sizeof(uint32_t), pt, pt_len);
    pt=pt_seq;
    pt_len+=sizeof(uint32_t);

    int aad_ct_len_net = htonl(pt_len); //Since we use GCM ciphertext == plaintext
    if(session_key_clientToClient==NULL){
        cerr << " Null key " << endl;
        return 0;
    }
    uint ct_len = auth_enc_encrypt(pt, pt_len, (uchar*)&aad_ct_len_net, sizeof(uint), session_key_clientToClient, &tag, &iv, &ct);
    if(ct_len == 0){
        cerr << "auth_enc_encrypt failed" << endl;
        safe_free(pt, pt_len);
        free(iv);
        free(tag);
        free(ct);
        free(pt_seq);
        return 0;
    }

    if(ct_len > UINT_MAX - header_len){
        cerr << " Integer overflow " << endl;
        safe_free(pt, pt_len);
        free(iv);
        free(tag);
        free(ct);
        free(pt_seq);
        return 0;
    }
    uint msg_to_send_len = ct_len + header_len;
    uint bytes_copied = 0;
    *msg_to_send = (uchar*)malloc(msg_to_send_len);
    if(!(*msg_to_send)){
        errorHandler(MALLOC_ERR);
        safe_free(pt, pt_len);
        free(iv);
        free(tag);
        free(ct);
        free(pt_seq);
        return 0;
    }

    memcpy((*msg_to_send) + bytes_copied, &aad_ct_len_net, sizeof(uint32_t));
    bytes_copied += sizeof(uint32_t);
    memcpy((*msg_to_send) + bytes_copied, iv, IV_DEFAULT);
    bytes_copied += IV_DEFAULT;
    memcpy((*msg_to_send) + bytes_copied, tag, TAG_DEFAULT);
    bytes_copied += TAG_DEFAULT;
    memcpy((*msg_to_send) + bytes_copied, ct, ct_len);
    bytes_copied += ct_len;

    if(bytes_copied!=msg_to_send_len)
        cerr << " Warning " << bytes_copied << " != " << msg_to_send_len << endl;

    safe_free(pt, pt_len);
    free(iv);
    free(tag);
    free(ct);
    if(send_counter_client_client==UINT32_MAX)
        return 0;
    send_counter_client_client++;
    return bytes_copied;
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
    if(comm_socket_id<0)
        return 0;
    if(pt==NULL)
        return 0;
    int ret;
    uchar *tag, *iv, *ct, *aad;
    uint aad_len;
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT;

    // adding sequence number
    uint32_t counter_n=htonl(send_counter);
    uchar* pt_seq = (uchar*)malloc(pt_len+sizeof(uint32_t));
    if(!pt_seq){
        safe_free(pt, pt_len);
        return 0;
    }
    memcpy(pt_seq , &counter_n, sizeof(uint32_t));
    memcpy(pt_seq+ sizeof(uint32_t), pt, pt_len);
    pt=pt_seq;
    pt_len+=sizeof(uint32_t);
 
    int aad_ct_len_net = htonl(pt_len); //Since we use GCM ciphertext == plaintext
    if(session_key_clientToServer==NULL){
        cerr << " Null key " << endl;
        return 0;
    }
    uint ct_len = auth_enc_encrypt(pt, pt_len, (uchar*)&aad_ct_len_net, sizeof(uint), session_key_clientToServer, &tag, &iv, &ct);
    if(ct_len == 0){
        cerr << "auth_enc_encrypt failed" << endl;
        free(iv);
        free(tag);
        free(ct);
        return 0;
    }
    
    if(ct_len > UINT_MAX - header_len){
        cerr << " Integer overflow " << endl;
        safe_free(pt, pt_len);
        free(iv);
        free(tag);
        free(ct);
        return 0;
    }
    uint msg_to_send_len = ct_len + header_len;
    uint bytes_copied = 0;
    uchar* msg_to_send = (uchar*)malloc(msg_to_send_len);
    if(!msg_to_send){
        errorHandler(MALLOC_ERR);
        free(iv);
        free(tag);
        free(ct);
        safe_free(pt, pt_len);
        return 0;
    }

    memcpy(msg_to_send + bytes_copied, &aad_ct_len_net, sizeof(uint));
    bytes_copied += sizeof(uint);
    memcpy(msg_to_send + bytes_copied, iv, IV_DEFAULT);
    bytes_copied += IV_DEFAULT;
    memcpy(msg_to_send + bytes_copied, tag, TAG_DEFAULT);
    bytes_copied += TAG_DEFAULT;
    memcpy(msg_to_send + bytes_copied, ct, ct_len);
    bytes_copied += ct_len;
   
    safe_free(pt, pt_len);

    ret = send(comm_socket_id, msg_to_send, msg_to_send_len, 0);
    if(ret <= 0 || ret != msg_to_send_len){
        errorHandler(SEND_ERR);
        free(iv);
        free(tag);
        free(ct);
        safe_free(msg_to_send, msg_to_send_len);
        return 0;
    }
    if(send_counter==UINT32_MAX){
        errorHandler(SEND_ERR);
        free(iv);
        free(tag);
        free(ct);
        safe_free(msg_to_send, msg_to_send_len);
        return 0;
    }
    send_counter++;

    safe_free(msg_to_send, msg_to_send_len);

    free(iv);
    free(tag);
    free(ct);
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
    if(sock_id<0)
        return -1;
    if(cmdToSend==NULL)
        return -1;
    uint32_t net_id;
    unsigned char* pt = NULL;
    uint32_t pt_len = (cmdToSend->opcode==CHAT_CMD || cmdToSend->opcode==STOP_CHAT)? sizeof(uint8_t)+sizeof(uint32_t) : sizeof(uint8_t);
    pt = (unsigned char*)malloc(pt_len);
    if(!pt)
        return -1;

    memcpy(pt, &(cmdToSend->opcode), sizeof(uint8_t));
    int stop=0;
    if(cmdToSend->opcode==CHAT_CMD || cmdToSend->opcode==STOP_CHAT) {
        if(cmdToSend->opcode==STOP_CHAT){
            cmdToSend->userId = peer_id;
            stop=1;
        }
            
        net_id = htonl(cmdToSend->userId);
        memcpy(pt+sizeof(uint8_t), &net_id, sizeof(uint32_t));
    }

    int ret = send_secure(sock_id, pt, pt_len);
    if(ret==0){
        safe_free(pt, pt_len);
        return -1;
    }
    safe_free(pt, pt_len);
    if(stop){
        send_counter_client_client=0;
        receive_counter_client_client=0;
    }
    return 0;
}

/**
 * @brief It send the message to the server
 * 
 * @param sock_id socket id
 * @param msgToSend data structure that contains the info for the message
 * @return -1 in case of error, 0 otherwise
 */
int send_message(int sock_id, genericMSG* msgToSend)
{
    if(sock_id<0)
        return -1;
    if(msgToSend==NULL)
        return -1;
    unsigned char* msgInternalPart = NULL; // nonce for client + msg for client
    uint32_t msgInternalPart_len = prepare_msg_for_client(msgToSend->payload, msgToSend->length, &msgInternalPart);
    if(msgInternalPart_len==0)
        return -1;
    if(msgInternalPart_len>UINT32_MAX-(sizeof(uint8_t)+sizeof(uint32_t))){
        cerr << " Integer Overflow " << endl;
        return -1;
    }
    uint32_t msg_len = msgInternalPart_len+sizeof(uint8_t)+sizeof(uint32_t);
    unsigned char* msg = (unsigned char*)malloc(msg_len);
    if(!msg){
        safe_free(msgInternalPart, msgInternalPart_len);
        return -1;
    }

    int bytes_allocated = 0;
    
    uint32_t net_peer_user_id = htonl(peer_id);
    memcpy((void*)msg, &(msgToSend->opcode), sizeof(uint8_t));
    bytes_allocated += sizeof(uint8_t);
    memcpy((void*)(msg+bytes_allocated), &(net_peer_user_id), sizeof(uint32_t));
    bytes_allocated += sizeof(uint32_t);
    memcpy((void*)(msg+bytes_allocated), msgInternalPart, msgInternalPart_len);
    bytes_allocated += msgInternalPart_len;

    if(bytes_allocated!=msg_len)
        cout << " WARNING - Something is going wrong " << endl;

    int ret = send_secure(sock_id, msg, msg_len);
    if(ret==0){
        cerr << " send secure failed " << endl;
        safe_free(msgInternalPart, msgInternalPart_len);
        safe_free(msg, msg_len);
        return -1;
    }

    // safe_free(msgToSend->payload, msgToSend->length); not needed because free inside prepare_msg_for_client
    safe_free(msgInternalPart, msgInternalPart_len);
    safe_free(msg, msg_len);

    return 0;
}

/**
 * @brief Receive a message sent by the other communication party and forwarded by the server
 * 
 * @param sock_id socket id
 * @param msg string where the received message is inserted
 * @return int -1 id error, 0 otherwise
 */
int receive_message(int sock_id, string& msg, unsigned char* msgReceived, uint32_t msgReceived_len)
{
    if(sock_id<0)
        return -1;
    if(msgReceived==NULL)
        return -1;
    unsigned char* pt = NULL;
    uint32_t pt_len = open_msg_by_client(msgReceived, msgReceived_len, &pt);
    if(pt_len<=0){
        return -1;
    }
    msg = (string)((char*)pt);
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
    if(sock_id<0)
        return -1;
    unsigned char* plaintext = NULL;
    int pt_len = recv_secure(sock_id, &plaintext);
    if(pt_len==-1)
        return -1;

    // check opcode
    uint8_t opcode_rec;
    memcpy(&opcode_rec, plaintext+4, sizeof(uint8_t));

    if(opcode_rec!=USRID){
        cerr << " Error: wrong opcode " << endl;
        free(plaintext);
        return -1;
    }

    int loggedUser_id_net;
    memcpy(&loggedUser_id_net, plaintext+sizeof(uint32_t)+1, sizeof(uint32_t));
    loggedUser_id = ntohl(loggedUser_id_net);  
    return 0;
}

/**
 * @brief Send a negative response to the server after a chat request
 * 
 * @param sock_id socket id
 * @param refused_user id of the user rejected, it must be in network order
 * @return -1 in case of error, 0 otherwise
 */
int automatic_neg_response(int sock_id, int refused_user)
{
    if(sock_id<0)
        return -1;

    if(ntohl(refused_user)<0 || ntohl(refused_user)>REGISTERED_USERS)
        return -1;
    
    
    uint32_t risp_buff_size = sizeof(uint8_t)+sizeof(int);
    unsigned char* risp_buff = (unsigned char*)malloc(risp_buff_size);
    if(!risp_buff)
        return -1;
            
    uint8_t response = CHAT_NEG;
    memcpy(risp_buff, (void*)&response, sizeof(uint8_t));
    memcpy(risp_buff+1, (void*)&refused_user, sizeof(int));
    
    int ret = send_secure(sock_id, risp_buff, risp_buff_size);
    if(ret==-1){
        free(risp_buff);
        return -1;
    }

    free(risp_buff);
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
    if(sock_id<0)
        return -1;
    // If the authentication is done with another client with the word "server" indicates the other client
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
    int peer_id_net = htonl(peer_id);
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
            cout << "Who are you? " << endl;
            cout << "> ";
            cin >> loggedUser;
            if(cin.fail()){
                cin.clear();
                cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                return -1;
            }
            cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            if(loggedUser.size()+1>MAX_USERNAME_SIZE)
                tooBig = true;
        }while(tooBig);
    }

    /*************************************************************
     * M1 - Send R,username to the server
     *************************************************************/
    // Nonce Generation
    nonce = (unsigned char*)malloc(NONCE_SIZE);
    if(!nonce)
        return -1;
    random_generate(NONCE_SIZE, nonce);

    // Preparation of the username
    if(ver==AUTH_CLNT_SRV){
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
        memcpy(msg_auth_1+msg_bytes_written, (void*)&peer_id_net, sizeof(int));
        msg_bytes_written += sizeof(int);
        memcpy(msg_auth_1+msg_bytes_written, nonce, NONCE_SIZE);
        msg_bytes_written += NONCE_SIZE;
    }

    // Send the message to the server
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
    // wait for nonce
    if(ver==AUTH_CLNT_CLNT){
        uint8_t op_tmp;
        uint32_t read_tmp;
        do{
            msg2_pt_len = recv_secure(sock_id, &msg2_pt);
            if(msg2_pt_len==-1)
                return -1;
    
            read_tmp = sizeof(uint32_t); // seq number read
            memcpy(&op_tmp, msg2_pt+read_tmp, sizeof(uint8_t));
            read_tmp += sizeof(uint8_t);

            if(op_tmp==CHAT_CMD){
                // automatic refuse
                int rejected_user;
                memcpy(&rejected_user, msg2_pt+read_tmp, sizeof(uint32_t));
                ret = automatic_neg_response(sock_id, rejected_user);
                if(ret==-1){
                    free(nonce);
                    return -1;
                }
            }
            else if(op_tmp!=AUTH){
                free(nonce);
                return -1;
            }
        }while(op_tmp!=AUTH);
    }
    uint32_t read_from_msg2 = sizeof(uint32_t) + sizeof(uint8_t); // seq number already read in recv_secure and opcode already handled
    
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
        read_from_msg2 += sizeof(int); // because of there is the user id but i am not interested in it
        memcpy(server_nonce, msg2_pt + read_from_msg2, NONCE_SIZE);
        read_from_msg2 += NONCE_SIZE;
    }

    // Read the length of the DH server pub key
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
        if(read_from_msg2 + dh_pub_srv_key_size > msg2_pt_len){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            return -1;
        }
        memcpy(dh_server_pubkey, msg2_pt+read_from_msg2, dh_pub_srv_key_size);
        read_from_msg2 += dh_pub_srv_key_size;
    }

    // Read signature length
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
        if(read_from_msg2 + len_signature > msg2_pt_len){
            free(server_nonce);
            free(nonce);
            free(dh_server_pubkey);
            return -1;
        }
        memcpy(signature, msg2_pt+read_from_msg2, len_signature);
        read_from_msg2 += len_signature;
    }
    
    // Read certificate length
    if(ver==AUTH_CLNT_SRV){
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
    len_signed_msg = NONCE_SIZE*2+dh_pub_srv_key_size;
    signed_msg = (unsigned char*)malloc(len_signed_msg);
    if(!signed_msg){
        cerr<<" no msg "<<endl;
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
            cerr << " The signature is not valid " << endl;
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
        ret = verify_sign_pubkey(signature, len_signature, signed_msg, len_signed_msg, peer_pub_key, PUBKEY_DEFAULT_SER);
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
    void* eph_dh_privKey = NULL;
    unsigned char* eph_dh_pubKey = NULL; 
    uint32_t eph_dh_pubKey_len;   
    ret = eph_key_generate(&eph_dh_privKey, &eph_dh_pubKey, &eph_dh_pubKey_len);
    if(ret!=1){
        cerr<<" error generating eph keys "<<endl;
        free(server_nonce);
        free(dh_server_pubkey);
        free(server_cert);
        return -1;
    }

    /*************************************************************
     * M3 - Send to the server my DHpubKey and the nonce R2
     *************************************************************/
    // Preparation of the message to sign
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

    uint32_t n_eph_dh_pubKey_len=htonl(eph_dh_pubKey_len);
    uint32_t n_client_sign_len=htonl(client_sign_len);
    msg_bytes_written = 0;
    if(ver==AUTH_CLNT_CLNT){
        uint8_t op_tmp = AUTH;
        memcpy(msg_to_send_M3+msg_bytes_written, &op_tmp, sizeof(uint8_t));
        msg_bytes_written += sizeof(uint8_t);
        memcpy(msg_to_send_M3+msg_bytes_written, &peer_id_net, sizeof(int));
        msg_bytes_written += sizeof(int);
    }
    memcpy(msg_to_send_M3 + msg_bytes_written, &n_eph_dh_pubKey_len, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(msg_to_send_M3+ msg_bytes_written, eph_dh_pubKey, eph_dh_pubKey_len);
    msg_bytes_written += eph_dh_pubKey_len;
    memcpy(msg_to_send_M3 + msg_bytes_written, &n_client_sign_len, sizeof(uint32_t));
    msg_bytes_written += sizeof(uint32_t);
    memcpy(msg_to_send_M3 + msg_bytes_written, client_signature, client_sign_len);
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

    // Send the message to send to the server
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
    if(sock_id<0)
        return -1;
    int ret;
    int peer_id_net = htonl(peer_id);
    uint8_t op_rec;
    uint32_t id_dest, id_dest_net;
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
    uint8_t op_tmp_checker;
    uint32_t read_tmp_checker;

    do{
        pt_M1_len = recv_secure(sock_id, &pt_M1);
        if(pt_M1_len<=0){
            cerr << " Error during M1 reception in authentication_receiver " << endl;
            safe_free(R1, NONCE_SIZE);
            return -1;
        }
    
        read_tmp_checker = sizeof(uint32_t); // seq number read
        memcpy(&op_tmp_checker, pt_M1+read_tmp_checker, sizeof(uint8_t));
        read_tmp_checker += sizeof(uint8_t);

        if(op_tmp_checker==CHAT_CMD){
            // automatic refuse
            int rejected_user;
            memcpy(&rejected_user, pt_M1+read_tmp_checker, sizeof(uint32_t));
            ret = automatic_neg_response(sock_id, rejected_user);
            if(ret==-1){
                safe_free(R1, NONCE_SIZE);
                return -1;
            }
        }
        else if(op_tmp_checker!=AUTH){
            safe_free(R1, NONCE_SIZE);
            return -1;
        }
    }while(op_tmp_checker!=AUTH);

    uint32_t bytes_read = sizeof(uint32_t); // Because sequence number already read in recv_secure

    // Double check
    memcpy(&op_rec, pt_M1+bytes_read, sizeof(uint8_t));
    bytes_read += sizeof(uint8_t);
    if(op_rec!=AUTH){
        cerr << " Wrong opcode received " << endl;
        free(R1);
        safe_free(pt_M1, pt_M1_len);
    }
    memcpy(&id_dest_net, pt_M1+bytes_read, sizeof(uint32_t));
    id_dest = ntohl(id_dest_net);
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
        cerr << "Error on EPH_KEY_GENERATE" << endl;
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }

    //Generate nuance R2
    ret = random_generate(NONCE_SIZE, R2);
    if(ret != 1){
        cerr <<  "Error on random_generate" << endl;
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }

    uint32_t M2_to_sign_length = (NONCE_SIZE*2) + eph_pubkey_s_len;
    uint32_t M2_signed_length;
    uchar* M2_signed;
    uchar* M2_to_sign = (uchar*)malloc(M2_to_sign_length);

    if(!M2_to_sign){
        cerr << "Error on M2_to_sign" << endl;
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }

    memcpy(M2_to_sign, R1, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + NONCE_SIZE), R2, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + (2*NONCE_SIZE)), eph_pubkey_s, eph_pubkey_s_len);

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

    
    ret = sign_document(M2_to_sign, M2_to_sign_length, privKey_file, NULL, &M2_signed, &M2_signed_length);
    if(ret != 1){
        cerr << "Error on signing part on M2" << endl;
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
    if(M2_signed_length > UINT32_MAX -(sizeof(uint8_t) + sizeof(int) + NONCE_SIZE + sizeof(int)+ sizeof(int))){
        cerr << " Integer Overflow" << endl;
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }
    if(eph_pubkey_s_len>UINT_MAX-(sizeof(uint8_t) + sizeof(int) + NONCE_SIZE + sizeof(int)+ sizeof(int) + M2_signed_length)){
        cerr << " Integer Overflow " << endl;
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }
    uint M2_size = sizeof(uint8_t) + sizeof(int) + NONCE_SIZE + sizeof(int) + eph_pubkey_s_len + sizeof(int) + M2_signed_length;
    uint offset = 0;
    uchar* M2 = (uchar*)malloc(M2_size);
    if(!M2){
        cerr << "Error during malloc for M2" << endl;
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }
    uint eph_pubkey_s_len_net = htonl(eph_pubkey_s_len);
    uint M2_signed_length_net = htonl(M2_signed_length);
   
    uint8_t opcode = AUTH;
    memcpy(M2+offset, &opcode, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    memcpy(M2+offset, &peer_id_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy((void*)(M2 + offset), R2, NONCE_SIZE);
    offset += NONCE_SIZE;
    memcpy((void*)(M2 + offset), &eph_pubkey_s_len_net, sizeof(uint));
    offset += sizeof(uint);
    memcpy((void*)(M2 + offset), eph_pubkey_s, eph_pubkey_s_len);
    offset += eph_pubkey_s_len;
    memcpy((void*)(M2 + offset), &M2_signed_length_net ,sizeof(uint));
    offset += sizeof(uint);
    memcpy((void*)(M2 + offset), M2_signed,M2_signed_length);
    offset += M2_signed_length;


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

    cout << "Wait ..."<< endl;
    do{
       msg3_len = recv_secure(sock_id, &msg3);
       if(msg3_len <= 0){
            cerr << " Error in recv_secure during M3 reception " << endl;
            safe_free(R2, NONCE_SIZE);
            safe_free_privkey(eph_privkey_s);
            return -1;
        }
    
        read_tmp_checker = sizeof(uint32_t); // seq number read
        memcpy(&op_tmp_checker, msg3+read_tmp_checker, sizeof(uint8_t));
        read_tmp_checker += sizeof(uint8_t);
        if(op_tmp_checker==CHAT_CMD){
            // automatic refuse
            int rejected_user;
            memcpy(&rejected_user, msg3+read_tmp_checker, sizeof(uint32_t));
            ret = automatic_neg_response(sock_id, rejected_user);
            if(ret==-1){
                safe_free(R1, NONCE_SIZE);
                return -1;
            }
        }
        else if(op_tmp_checker!=AUTH){
            safe_free(R1, NONCE_SIZE);
            return -1;
        }
    }while(op_tmp_checker!=AUTH);
    

    bytes_read = 4; // seq number already read in recv secure

    memcpy(&op_rec, msg3+bytes_read, sizeof(uint8_t));
    bytes_read += sizeof(uint8_t);
    if(op_rec!=AUTH){
        cerr << " Wrong opcode received " << endl;
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
    }
    memcpy(&id_dest_net, msg3+bytes_read, sizeof(uint32_t));
    id_dest = ntohl(id_dest_net);
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

    uchar* eph_pubkey_c = (uchar*)malloc(eph_pubkey_c_len);
    if(!eph_pubkey_c ){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
        return -1;
    }

    if(bytes_read + eph_pubkey_c_len > msg3_len){
        cerr << " Error in message len " << endl;
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
        safe_free(eph_pubkey_c,eph_pubkey_c_len);
        return -1;
    }
    memcpy(eph_pubkey_c, msg3+bytes_read, eph_pubkey_c_len);
    bytes_read += eph_pubkey_c_len;

    uint32_t m3_signature_len;
    memcpy(&m3_signature_len, msg3+bytes_read, sizeof(uint32_t));
    bytes_read += sizeof(uint32_t);
    m3_signature_len = ntohl(m3_signature_len);

    uchar* M3_signed = (uchar*)malloc(m3_signature_len);
    if(!M3_signed){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        return -1;
    }

    if(bytes_read + m3_signature_len > msg3_len){
        cerr << " Error in message len " << endl;
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(msg3, msg3_len);
        safe_free(eph_pubkey_c,eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
    }
    memcpy(M3_signed, msg3+bytes_read, m3_signature_len);
    bytes_read += m3_signature_len;

    safe_free(msg3, msg3_len);

    if(eph_pubkey_c_len>UINT_MAX-NONCE_SIZE){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
    }
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

    if(peer_pub_key==NULL){
        cerr << " Peer public key not present " << endl;
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
    }

    ret = verify_sign_pubkey(M3_signed, m3_signature_len, m3_document, m3_document_size, peer_pub_key, PUBKEY_DEFAULT_SER);
    if(ret == 0){
        cerr << "Failed sign verification on M3" << endl;
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
    shared_secret_len = derive_secret(eph_privkey_s, eph_pubkey_c, eph_pubkey_c_len, &shared_secret);
    if(shared_secret_len == 0){
        cerr << "Failed derive secret" << endl;
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free_privkey(eph_privkey_s);
        return -1;    
    }

    session_key_clientToClient_len = default_digest(shared_secret, shared_secret_len, &session_key_clientToClient);
    if(session_key_clientToClient_len == 0){
        cerr << "Failed digest computation of the secret" << endl;
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(shared_secret, shared_secret_len);
        safe_free_privkey(eph_privkey_s);
        return -1;    
    }
 
    safe_free(eph_pubkey_c, eph_pubkey_c_len);
    safe_free(shared_secret, shared_secret_len);
    
    cout << "AUTHENTICATION WITH " << peer_username << " SUCCESFULLY EXECUTED " << endl;
    return 0;
}

/**
 * @brief handle an incoming chat request
 * 
 * @param plaintext message received
 * @param pt_len message length
 * @return 1 if everything's ok, 0 on error(s)
 */
int chatRequestHandler(unsigned char* plaintext, uint32_t pt_len)
{
    if(plaintext==NULL)
        return 0;
    int ret;
    uint8_t opcode = NOT_VALID_CMD;
    uint8_t response;
    int id_cp;
    unsigned char* counterpart;
    uint size_username;
    char user_resp = 'a';
    unsigned char* risp_buff = NULL;
    size_t risp_buff_size = 0;
    uint32_t bytes_read = 5; // because I have already read the opcode and the seq number

    // Reading of the peer id
    memcpy(&id_cp, (plaintext + bytes_read), sizeof(int));
    bytes_read += sizeof(int);
    // htonl of id_cp is done afterwards
    
    // Read username length
    memcpy(&size_username, plaintext+bytes_read, sizeof(int));
    bytes_read += sizeof(int);
    size_username = ntohl(size_username);
    if(size_username>MAX_USERNAME_SIZE){
        cerr << " Username size too big " << endl;
        return 0;
    }
  
    // Read username peer
    counterpart = (unsigned char*)malloc(size_username+1); // +1 for string terminator
    if(!counterpart){
        cout << " malloc error for counterpart " << endl;
        return 0;
    }

    if(bytes_read+size_username>pt_len){
        cerr << " Errore in reading " << endl;
        return 0;
    }
    memcpy(counterpart, plaintext+bytes_read, size_username);
    bytes_read += size_username;
    counterpart[size_username] = '\0';

    // Read sender pubkey
    // Public key of an old peer
    if(peer_pub_key!=NULL){
        free(peer_pub_key);
        peer_pub_key = NULL;
    }
    peer_pub_key = (unsigned char*)malloc(PUBKEY_DEFAULT_SER);
    if(!peer_pub_key)
        return 0;    
    
    memcpy(peer_pub_key, plaintext+bytes_read, PUBKEY_DEFAULT_SER);
    bytes_read += PUBKEY_DEFAULT_SER;    
    if(peer_pub_key==NULL)
        return 0;

    if(isChatting){
        // Automatic response
        free(counterpart);
        ret = automatic_neg_response(sock_id, id_cp);
        if(ret==-1)
            return 0;
        return 1;
    }
    isChatting = true; // to avoid interference during this phase
    peer_id = ntohl(id_cp);
    
    cout << "\n**********************************************************" << endl;
    cout << "Do you want to chat with " << counterpart << " with user id " << peer_id << " ? (y/n)" << endl;
   
    while(user_resp!='y' && user_resp!='n') {
        cin >> user_resp;
        if(cin.fail()){
            cin.clear();
        }
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
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
        return 0;
    }
    
    memcpy((void*)risp_buff, (void*)&response, sizeof(uint8_t));
    memcpy((void*)(risp_buff+1), (void*)&id_cp, sizeof(int));

    ret = send_secure(sock_id, risp_buff, risp_buff_size);
    if(ret==-1){
        free(risp_buff);
        return 0;
    }
    free(risp_buff);

    if(response==CHAT_NEG){
        cout << " Chat refused " << endl;
        isChatting = false;
        return 1;
    }
    peer_username = (char*)counterpart;
    free(counterpart);
    peer_id = ntohl(id_cp);
    // AUTENTICAZIONE CLIENT-CLIENT
    cout << "Wait for authentication ... " << endl;
    if(response==CHAT_POS){
        ret = authentication_receiver(sock_id);
        if(ret==-1){
            cout << " Authentication with " << peer_username <<" failed " << endl;
            return 0;
        }
    }
    else{
        cerr << " Something went wrong " << endl;
        return 0;
    }
    // I am now chatting with the user that request to contact me
    // Clean stdin by what we have digit previously
    cin.clear();
    fflush(stdin);
    cout << "\n ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << endl;
    cout << "                             CHAT                                   " << endl;
    cout << " All the commands are ignored in this section except for !stop_chat " << endl;
    cout << " Send a message to " <<  peer_username << endl;
    cout << " ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n" << endl;
    return 1;
}

/**
 * @brief Hanler of the command written by the user
 * 
 * @param userInput 
 * @return return -1 in case of error, 
 *      1 if no answer from the server is needed, 
 *      2 if an answer from the server is needed,
 *      3 if we the command is an !exit
 *      
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
                cout << " The user indicated is not in your user list or the user id is not valid - try to launch !users_online then try again " << endl;
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
            if(isChatting){
                cmdToSend.opcode = STOP_CHAT;
                isChatting = false;
            }
            else{
                no_comm_with_srv = true;
                cout << "You are not chatting " << endl;
            }
            break;
            
        case NOT_VALID_CMD:
            no_comm_with_srv = true;
            //BIO_dump_fp(stdout, (const char*)userInput.c_str(), userInput.length());
            cout << "Command Not Valid" << endl;
            break;
            
        default:
            no_comm_with_srv = true;                
            cout << "Command Not Valid" << endl;
            break;
        }      
    }else {
        /* ****************************************
        *          CHAT SECTION
        * *****************************************/
        msgGenToSend.opcode = CHAT_RESPONSE;
        msgGenToSend.length = userInput.size()+1; //+1 for the null terminator
        msgGenToSend.payload = (unsigned char*)malloc(msgGenToSend.length);
        if(!msgGenToSend.payload) {
            error = true;
            errorHandler(MALLOC_ERR);
            return -1;
        }
        strncpy((char*)msgGenToSend.payload, userInput.c_str(), msgGenToSend.length);  
    }
     
    if(no_comm_with_srv)
        return 1;
    /* ********************************
    *  COMMUNICATIONS WITH SERVER 
    * ********************************/
    if(isChatting && cmdToSend.opcode!=STOP_CHAT) {
        ret = send_message(sock_id, &msgGenToSend);
        if(ret!=0){
            error = true;
            errorHandler(SEND_ERR);
            return -1;
        }
        return 1;
    }
    else {
        // Send the command message to the server
        ret = send_command_to_server(sock_id, &cmdToSend);
        if(ret!=0){
            error = true;
            errorHandler(SEND_ERR);
            return -1;
        }

        if(cmdToSend.opcode==STOP_CHAT){
            cout << " \t\t    +++ Chat terminated +++\n" << endl;
            return 1;
        }
        if(cmdToSend.opcode==EXIT_CMD){
            return 3;
        }
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
    if(sock_id<0)
        return -1;
    uint8_t op;
    int counterpart_id;
    int ret;

    unsigned char* plaintext = NULL;
    int pt_len = recv_secure(sock_id, &plaintext);
    if(pt_len==-1)
        return -1;
    // I read the first byte to understand which type of message the server is sending to me
    memcpy(&op, plaintext+sizeof(uint32_t), sizeof(uint8_t));

    /* ****************************************************************
    * Action to perform considering the things sent from the server
    * ****************************************************************/
    switch (op){
    case ONLINE_CMD:{
        ret = retrieveOnlineUsers(plaintext, pt_len);
        if(ret == 0){
            cout << " ** No users are online ** " << endl;
        }
        else if (ret==-1){
            error = true;
            errorHandler(GEN_ERR);
            free(plaintext);
            return -1;
        }
        else if(print_list_users(user_list)!=0){
            error = true;
            errorHandler(GEN_ERR);
            free(plaintext);
            return -1;
        }
        break;
    }
    case CHAT_POS:
    {
        // The server says that the client that I want to contact is available
        memcpy(&counterpart_id, plaintext+5, sizeof(int)); // +5 because I have already read the opcode and the seq number
        if(peer_username.empty()){
            cout << " DBG - Peer username is empty " << endl;
            error = true;
            errorHandler(GEN_ERR);
            free(plaintext);
            return -1;
        }
                    
        if(peer_id!=counterpart_id) {
            cout << " Server internal error: the user id requested and the one available does not match" << endl;
            break;
        }

        // Pub key of the peer
        if(peer_pub_key!=NULL){
            free(peer_pub_key); // old public key peer
            peer_pub_key = NULL;
        }
        peer_pub_key = (unsigned char*)malloc(PUBKEY_DEFAULT_SER);
        if(!peer_pub_key){
            errorHandler(MALLOC_ERR);
            free(plaintext);
            return -1;
        }
        memcpy(peer_pub_key, plaintext+5+sizeof(int), PUBKEY_DEFAULT_SER);
        if(peer_pub_key==NULL){
            cerr << " Error in receiving peer public key " << endl;
            free(plaintext);
            return -1;
        }

        ret = authentication(sock_id, AUTH_CLNT_CLNT);
        if(ret!=0){
            cout << " Authentication with " << peer_username << " failed " << endl;
            free(plaintext);
            return -1;
        }
        isChatting = true;
        cout << "AUTHENTICATION WITH " << peer_username << " SUCCESFULLY EXECUTED " << endl;
        cout << "\n ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ " << endl;
        cout << "                             CHAT                                   " << endl;
        cout << " All the commands are ignored in this section except for !stop_chat " << endl;
        cout << " Send a message to " <<  peer_username << endl;
        cout << " ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n" << endl;
    }  
    break;
    case CHAT_NEG:
        cout << " The user has refused the request " << endl;
        break;

    case CHAT_RESPONSE:
    {
        string message;
        ret = receive_message(sock_id, message, plaintext, pt_len);
        if(ret!=0) {
            error = true;
            perror("chat response");
            errorHandler(REC_ERR);
            free(plaintext);
            return -1;
        }

        if(peer_username.empty()){
            error = true;
            errorHandler(GEN_ERR);
            free(plaintext);
            return -1;
        }
        cout << " \t\t\t\t " << peer_username << " -> " << message << endl;
    }
    break;
    case CHAT_CMD:
        ret = chatRequestHandler(plaintext, pt_len);
        if(ret<=0) {
            error = true;
            perror("chat command");
            errorHandler(REC_ERR);
            free(plaintext);
            return -1;
        }
    break;
    case STOP_CHAT:
        isChatting = false;
        free(peer_pub_key);
        peer_pub_key = NULL;
        send_counter_client_client=0;
        receive_counter_client_client=0;
        cout << " \t\t +++ Chat terminated by " << peer_username << " +++\n" << endl;
        break;
    default:{
        error = true;
        errorHandler(SRV_INTERNAL_ERR);
        free(plaintext);
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
    cout << "--- AUTHENTICATION DONE --- " << endl; 
    cout << "HELLO " << loggedUser << "\n" << endl;

    while(true) {
        // fdlist must be initialized after each use of the select
        FD_ZERO(&fdlist);
        FD_SET(fileno(stdin), &fdlist);
        FD_SET(sock_id, &fdlist);

        int howManyDescr = 0;
        int max_descr = (fileno(stdin)>=sock_id)?fileno(stdin):sock_id;
        max_descr++;
        howManyDescr = select(max_descr, &fdlist, NULL, NULL, NULL);
        
        switch(howManyDescr){
        case 0:
            printf("SELECT RETURN 0\n");
            break;
        case -1:
            perror("select");
            break;
        default:
            if (FD_ISSET(fileno(stdin), &fdlist)!=0) {
                // The output must be read even if need_server_answer is false
                fseek(stdin,0,SEEK_END);
                getline(cin, userInput); // command from terminal arrived
                if(!need_server_answer){
                    ret = commandHandler(userInput);
                    if(ret<0){
                        error = true;
                        errorHandler(GEN_ERR);
                        goto close_all;
                    }
                }
                if(ret==2)
                    need_server_answer=true;
                if(ret==3)
                    goto close_all;
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
       
close_all:
    if(msgGenToSend.payload)
        free(msgGenToSend.payload);
    if(peer_pub_key)
        free(peer_pub_key);
    if(session_key_clientToClient)
        safe_free(session_key_clientToClient, session_key_clientToClient_len);
    if(server_cert)
        free(server_cert);
    if(session_key_clientToServer)
        safe_free(session_key_clientToServer, session_key_clientToServer_len);

    if(user_list)
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