#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <limits.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <errno.h>
#include <fcntl.h>
#include "constant.h"
#include "util.h"
#include "crypto.h"

using namespace std;
using uchar=unsigned char;
typedef void (*sighandler_t)(int);



/*
* socket_id: if equal to -1 the user is not connected to the service
*/
struct user_info {
    string username;
    int socket_id;
    // string msg_queue_key;
    // int to_relay_user_id;  // -1 in case of nothing or user_id of the peer who set the request to chat
};


struct msg_to_relay{
    long type;
    char buffer[RELAY_MSG_SIZE];
};

//---------------- GLOBAL VARIABLES ------------------//
int client_user_id;
int comm_socket_id;
msg_to_relay relay_msg;

//Parameters of connection
const char *srv_ipv4 = "127.0.0.1";
const int srv_port = 4242;
int peer_user_id_to_exchange;
void* server_privk;

uchar* session_key;
uint32_t session_key_len;

//Handling mutual exclusion for accessing the user datastore
const char* sem_user_store_name = "/user_store";
const char* message_queue_name = "/user_message_queue";

void* create_shared_memory(ssize_t size);

//Shared memory for storing data of users
void* shmem = create_shared_memory(sizeof(user_info)*REGISTERED_USERS);
int send_secure(int comm_socket_id, uchar* pt, int pt_len);
int recv_secure(int comm_socket_id, unsigned char** plaintext);
    
void* create_shared_memory(ssize_t size){
    int protection = PROT_READ | PROT_WRITE; //Processes can read/write the contents of the memory
    int visibility = MAP_SHARED | MAP_ANONYMOUS; //Memory pages are shared across processes
    return mmap(NULL, size, protection, visibility, -1, 0);
}


// ---------------------------------------------------------------------
// FUNCTIONS for accessing to the USER DATASTORE
// ---------------------------------------------------------------------
/**
 * @return -1: username not present, 0: successfully written socket data
 */

void sem_enter(sem_t* sem_id){
    vlog("sem_enter");
    if(sem_id == SEM_FAILED)
        errorHandler(SEM_OPEN_ERR);
    if(sem_wait(sem_id) < 0)
        errorHandler(SEM_WAIT_ERR);
}

void sem_exit(sem_t* sem_id){
    vlog("sem_exit");
    if(sem_post(sem_id) < 0)
        errorHandler(SEM_POST_ERR);
    if(sem_close(sem_id) < 0)
        errorHandler(SEM_CLOSE_ERR);
}


/**
 * @brief test socket of communication in the user data store
 * @return return 0 if username not found, 1 otherwise
 */
int set_user_socket(string username, int socket){

    sem_t* sem_id= sem_open(sem_user_store_name, O_CREAT, 0600, 1);
    sem_enter(sem_id);
    
    user_info* user_status = (user_info*)shmem;
    int found = 0;
    for(int i=0; i<REGISTERED_USERS; i++){
        if(user_status[i].username.compare(username) == 0){
            user_status[i].socket_id = socket;
            log("Set socket of " + username + " correctly");
            found = 1;
            break;
        }
    }

    sem_exit(sem_id);
    return found;
}

void print_user_data_store(){
    sem_t* sem_id= sem_open(sem_user_store_name, O_CREAT, 0600, 1);
    sem_enter(sem_id);
    
    user_info* user_status = (user_info*)shmem;
    cout << "****** USER STATUS *******" << endl;
    for(int i=0; i<REGISTERED_USERS; i++){
        cout << "[" << i << "] " << user_status[i].username << " | " << user_status[i].socket_id << " | " << " | "  << ((user_status[i].socket_id==-1)?"offline":"online") << endl;
    }

    sem_exit(sem_id);
}

/**
 * Need to free return value of this function 
 */
user_info* get_user_datastore_copy(){
    sem_t* sem_id= sem_open(sem_user_store_name, O_CREAT, 0600, 1);
    sem_enter(sem_id);

    //Obtain a copy of the user datastore    
    user_info* user_status = (user_info*)malloc(REGISTERED_USERS*sizeof(user_info));
    if(!user_status)
        errorHandler(MALLOC_ERR);
    memcpy(user_status, shmem, REGISTERED_USERS*sizeof(user_info));

    sem_exit(sem_id);
    return user_status;
}


//Hardcoded content due to the fact that users are already registered
void initialize_user_info(user_info* user_status){
    vector<string> usernames {"alice", "bob", "charlie", "dave", "ethan"};

    for(int i=0; i < REGISTERED_USERS; i++){
        user_status[i].username = usernames[i];
        // user_status[i].msg_queue_key = usernames[i] + "_queue";
        user_status[i].socket_id = -1;
        // user_status[i].to_relay_user_id = -1;
    }
}


int get_user_id_by_username(string username){
    log("Entering get id by username");
    sem_t* sem_id= sem_open(sem_user_store_name, O_CREAT, 0600, 1);
    sem_enter(sem_id);
    
    int ret = -1;
    user_info* user_status = (user_info*)shmem;
    for(int i=0; i<REGISTERED_USERS; i++){
        if(user_status[i].username.compare(username) == 0){
            log("Found username " + username + " in the datastore with user_id " + to_string(i));
            ret = i;
            break;
        }
    }
    sem_exit(sem_id);
    return ret;
}


string get_username_by_user_id(size_t id){
    log("Entering get username by id");
    if(id >= REGISTERED_USERS){
        log(" ERR - User_id not present");
        errorHandler(GEN_ERR);
    }

    sem_t* sem_id= sem_open(sem_user_store_name, O_CREAT, 0600, 1);
    sem_enter(sem_id);

    user_info* user_status = (user_info*)shmem;
    string username = user_status[id].username;
    log("Obtained username of " + username);
    sem_exit(sem_id);
    return username;
}

/**
 *  @brief Removes traces of other execution due to the utilization of "named" data structures (semaphores and pipes) that can survive
 */
void prior_cleanup(){
    sem_unlink(sem_user_store_name); //Remove traces of usage for older execution  
    key_t key = ftok(message_queue_name, 65); 
    vlog("Key of ftok returned is " + to_string(key));
    int msgid = msgget(key, 0666 | IPC_CREAT);
    vlog("msgid is " + to_string(msgid));
    msgctl(msgid, IPC_RMID, NULL);
    msgid = msgget(key, 0666 | IPC_CREAT);
    struct msqid_ds buf;
    msgctl(msgid, IPC_STAT, &buf);
    // cout << "Current # of bytes on queue 	" << buf.__msg_cbytes << endl;
    cout << "Current # of messages on queue	" << buf.msg_qnum << endl;
    cout << "Maximum # of bytes on queue 	" << buf.msg_qbytes << endl;
    buf.msg_qbytes = 16384;
    int ret = msgctl(msgid, IPC_SET, &buf);
    msgctl(msgid, IPC_STAT, &buf);
    cout << "Current # of bytes on queue 	" << buf.__msg_cbytes << endl;
    cout << "Current # of messages on queue	" << buf.msg_qnum << endl;
    cout << "Maximum # of bytes on queue 	" << buf.msg_qbytes << endl;
    log("change size queue: " + to_string(ret));
}

// ---------------------------------------------------------------------
// FUNCTIONS of INTER-PROCESS COMMUNICATION
// ---------------------------------------------------------------------

/** 
 *  Send message to message queue of to_user_id
 *  @return 0 in case of success, -1 in case of error
 */
int relay_write(int to_user_id, msg_to_relay msg){
    log("Entering relay_write for " + to_string(to_user_id));

    msg.type = to_user_id + 1;
    
    //Write to the message queue
    key_t key = ftok(message_queue_name, 65); 
    vvlog("Key of ftok returned is " + to_string(key));
    int msgid = msgget(key, 0666 | IPC_CREAT);
    vvlog("msgid is " + to_string(msgid));

    // log("Relaying: ");
    // BIO_dump_fp(stdout, (const char*)msg.buffer, 600);

    msgsnd(msgid, &msg, sizeof(msg_to_relay), 0);
    return 0;
}

/**
 * @brief read from message queue of user_id (blocking)
 * @return -1 if no message has been read otherwise return the bytes copied
 **/
int relay_read(int user_id, msg_to_relay& msg, bool blocking){
    if(blocking)
        alarm(0);

    int ret = -1;
    log("Entering relay_read of " + to_string(user_id) + " [" + (blocking? "blocking": "no_wait") + "]");

    //Read from the message queue
    key_t key = ftok(message_queue_name, 65); 
    vlog("Key of ftok returned is " + to_string(key));
    //msg.type = 0;
    int msgid = msgget(key, 0666 | IPC_CREAT);
    vlog("msgid is " + to_string(msgid));
    
    ret = msgrcv(msgid, &msg, sizeof(msg), user_id+1, (blocking? 0: IPC_NOWAIT));
    if (ret == -1) {
        log("read nothing");
    }

    // log("Received: ");
    // BIO_dump_fp(stdout, (const char*)msg.buffer, 100);

    if(blocking)
        alarm(RELAY_CONTROL_TIME);
    return ret;
}


// ---------------------------------------------------------------------
// FUNCTIONS of HANDLING SIGNALS
// ---------------------------------------------------------------------


/**
 * @brief Handler that handles the SIG_ALARM, this represents the fact that every REQUEST_CONTROL_TIME the client must control for chat request
 * 
 * @param sig 
 */
void signal_handler(int sig)
{
    // Se viene chiamato durante una comunicazione durante client e server rompe tutto perchè la listen legge un byte dal
    // socket
    log("signal handler");
    int ret;
    uint8_t opcode;

                
    if(relay_read(client_user_id, relay_msg, false) != -1){
        //memcpy(&opcode, relay_msg.buffer[0], sizeof(uint8_t));
        opcode = relay_msg.buffer[0];
        log("Found request to relay with opcode: " + to_string(opcode));
        
        if(opcode == CHAT_CMD) {
            int username_length, username_length_net;
            memcpy(&username_length_net, (void*)(relay_msg.buffer + 5), sizeof(int));
            username_length = ntohl(username_length_net);
            log("USERNAME LENGTH: " + to_string(username_length));

            int msg_length = 9 + username_length + PUBKEY_DEFAULT_SER;

            // Send reply of the peer to the client
            ret = send_secure(comm_socket_id, (uchar*)relay_msg.buffer, msg_length);
            if(ret == 0){
                errorHandler(SEND_ERR);
                exit(1);
            }       
            log("Sent to client : ");    
            BIO_dump_fp(stdout, (const char*)relay_msg.buffer, msg_length);
        } else if(opcode == AUTH || opcode == CHAT_RESPONSE){
            int msg_len;
            memcpy(&msg_len, relay_msg.buffer + 1, sizeof(int)); //Added len field
            uchar* msg_to_send = (uchar*)malloc(msg_len);
            msg_to_send[0] = opcode;
            memcpy(msg_to_send + 1, relay_msg.buffer + 5, msg_len - 1);
            ret = send_secure(comm_socket_id, (uchar*)msg_to_send, msg_len);
            if(ret == 0){
                errorHandler(SEND_ERR);
                free(msg_to_send);
                exit(1);
            }       
            log("Sent to client : ");    
            BIO_dump_fp(stdout, (const char*)msg_to_send, msg_len);
            free(msg_to_send);
        // } else if(opcode == CHAT_RESPONSE){
        //     uint16_t msg_length_net, msg_length;
        //     memcpy(&msg_length_net, (void*)(relay_msg.buffer + 3), sizeof(uint16_t));
        //     msg_length = ntohs(msg_length_net);
            
        //     log("MSG LENGTH: " + msg_length);
        //     uint16_t total_plaintext_len = msg_length + 5;

        //     // Send reply of the peer to the client
        //     ret = send_secure(comm_socket_id, (uchar*)relay_msg.buffer, total_plaintext_len);
        //     if(ret == 0){
        //         errorHandler(SEND_ERR);
        //         exit(1);
        //     }

        //     log("Sent to client (pt): ");    
        //     BIO_dump_fp(stdout, (const char*)relay_msg.buffer, total_plaintext_len);
        } else {
            log("OPCODE not recognized (" + to_string(opcode) + ")");
        }
    }
                

    alarm(RELAY_CONTROL_TIME);
    return;
}


// ---------------------------------------------------------------------
// FUNCTIONS of SECURITY
// ---------------------------------------------------------------------

uint32_t send_counter=0;

/**
 * @brief perform a an authenticad encryption and then a send operation
 * @param pt: pointer to plaintext without sequence number
 * @return 1 in case of success, 0 in case of error 
 */
int send_secure(int comm_socket_id, uchar* pt, int pt_len){
    int ret;
    uchar *tag, *iv, *ct, *aad;
    //alarm(0);

    uint aad_len;
    // log("Plaintext to send:");
    // BIO_dump_fp(stdout, (const char*)pt, pt_len);
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT;

    // adding sequence number
    uint32_t counter_n=htonl(send_counter);
    cout <<" adding sequrnce number " << send_counter << endl;
    uchar* pt_seq = (uchar*)malloc(pt_len+sizeof(uint32_t));
    memcpy(pt_seq , &counter_n, sizeof(uint32_t));
    memcpy(pt_seq+ sizeof(uint32_t), pt, pt_len);
    pt=pt_seq;
    pt_len+=sizeof(uint32_t);
    log("Plaintext to send (with seq):");
    BIO_dump_fp(stdout, (const char*)pt, pt_len);

    int aad_ct_len_net = htonl(pt_len); //Since we use GCM ciphertext == plaintext
    int ct_len = auth_enc_encrypt(pt, pt_len, (uchar*)&aad_ct_len_net, sizeof(uint), session_key, &tag, &iv, &ct);
    if(ct_len == 0){
        log("auth_enc_encrypt failed");
        return 0;
    }
    // log("ct_len: " + to_string(ct_len)); 
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

    // log("Msg (authenticated and encrypted) to send, (copied " + to_string(bytes_copied) + " of " + to_string(msg_to_send_len) + "):");
    // BIO_dump_fp(stdout, (const char*)msg_to_send, msg_to_send_len);

    //-----------------------------------------------------------
    // Controllo encr/decr
    unsigned char* pt_test = NULL;
    int pt_len_test = auth_enc_decrypt(ct, ct_len, (uchar*)&aad_ct_len_net, sizeof(uint32_t), session_key, tag, iv, &pt_test);
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
    //alarm(RELAY_CONTROL_TIME);
    return 1;
}


uint32_t receive_counter=0;

//TODO: basically unmodified, maybe can be added to crypto.cpp
/**
 * @brief Receive in a secure way the messages sent by the server, decipher it and return the plaintext in the correspodent parameter. It
 * also control the sequence number
 * 
 * @param socket socket id
 * @param plaintext plaintext obtained by the decryption of the ciphertext
 * @return int plaintext length or -1 if error
 */
int recv_secure(int comm_socket_id, unsigned char** plaintext)
{
    log(" DBG - SECURE RECEIVE ");

    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT; 
    cout << " DBG - header_len: " << header_len << endl;
    uint32_t ct_len;
    unsigned char* ciphertext = NULL;
    uint32_t pt_len;
    int ret;
    //alarm(0);
    unsigned char* header = (unsigned char*)malloc(header_len);
    if(!header){
        cerr << " Error in malloc for header " << endl; 
        return -1;
    }
    unsigned char* iv = (unsigned char*)malloc(IV_DEFAULT);
    if(!iv){
        cerr << " Error in malloc for iv " << endl; 
        safe_free(header, header_len);
        return -1;
    }
    unsigned char* tag = (unsigned char*)malloc(TAG_DEFAULT);
    if(!tag){
        cerr << " Error in malloc for tag " << endl; 
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        return -1;
    }

    // Receive Header
    //cout << " DBG - Before recv " << endl;
    //BIO_dump_fp(stdout, (const char*)header, header_len);
    ret = recv(comm_socket_id, (void*)header, header_len, 0);
    if(ret <= 0 || ret != header_len){
        cerr << " Error in header reception " << ret << endl;
        BIO_dump_fp(stdout, (const char*)header, header_len);
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        return -1;
    }
    BIO_dump_fp(stdout, (const char*)header, header_len);

    // Open header
    memcpy((void*)&ct_len, header, sizeof(uint32_t));
    log(" ct_len :");
    BIO_dump_fp(stdout, (const char*)&ct_len, sizeof(uint32_t));

    memcpy(iv, header+sizeof(uint32_t), IV_DEFAULT);
    log(" iv :");
    BIO_dump_fp(stdout, (const char*)iv, IV_DEFAULT);

    memcpy(tag, header+sizeof(uint32_t)+IV_DEFAULT, TAG_DEFAULT);
    log(" tag :");
    BIO_dump_fp(stdout, (const char*)tag, TAG_DEFAULT);

    unsigned char* aad = (unsigned char*)malloc(sizeof(uint32_t));
    if(!aad){
        cerr << " Error in aad malloc " << endl;
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        return -1;
    }
    memcpy(aad, header, sizeof(uint32_t));
    log(" AAD : ");
    BIO_dump_fp(stdout, (const char*)aad, sizeof(uint32_t));

    // Receive ciphertext
    cout << " DBG - ct_len before ntohl is " << ct_len << endl;
    ct_len = ntohl(ct_len);
    cout << " DBG - ct_len real is " << ct_len << endl;

    ciphertext = (unsigned char*)malloc(ct_len);
    if(!ciphertext){
        cerr << " Error in malloc for ciphertext " << endl;
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        safe_free(aad, sizeof(uint32_t));
        return -1;
    }
    ret = recv(comm_socket_id, (void*)ciphertext, ct_len, 0);
    if(ret <= 0){
        cerr << " Error in AAD reception " << endl;
        safe_free(ciphertext, ct_len);
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        safe_free(aad, sizeof(uint32_t));
        return -1;
    }
    cout << " ciphertext is: " << endl;
    BIO_dump_fp(stdout, (const char*)ciphertext, ct_len);

    // Decryption
    cout<<"Session key:"<<endl;
    BIO_dump_fp(stdout, (const char*) session_key, 32);
    pt_len = auth_enc_decrypt(ciphertext, ct_len, aad, sizeof(uint32_t), session_key, tag, iv, plaintext);
    if(pt_len == 0 || pt_len!=ct_len){
        cerr << " Error during decryption " << endl;
        safe_free(*plaintext, pt_len);
        safe_free(ciphertext, ct_len);
        safe_free(tag, TAG_DEFAULT);
        safe_free(header, header_len);
        safe_free(iv, IV_DEFAULT);
        safe_free(aad, sizeof(uint32_t));
        return -1;
    }
    cout << " ciphertext is: " << endl;
    BIO_dump_fp(stdout, (const char*)ciphertext, ct_len);
    cout << " plaintext is " << endl;
    BIO_dump_fp(stdout, (const char*)*plaintext, pt_len);
    safe_free(ciphertext, ct_len);
    safe_free(tag, TAG_DEFAULT);
    safe_free(header, header_len);
    safe_free(iv, IV_DEFAULT);
    safe_free(aad, sizeof(uint32_t));

    // check seq number
    uint32_t sequece_number = ntohl(*(uint32_t*) (*plaintext));
    cout << " received sequence number " << sequece_number  << " aka " << *(uint32_t*) (*plaintext) << endl;
    cout << " Expected sequence number " << receive_counter << endl;
    if(sequece_number<receive_counter){
        cerr << " Error: wrong seq number " << endl;
        safe_free(*plaintext, pt_len);
        return -1;
    }
    receive_counter=sequece_number+1;
    //alarm(RELAY_CONTROL_TIME);
    return pt_len;
}


/**
 * @brief handle authentication with the client
 * @return user_id of the client or -1 if not present in the user store or in case of errors
 */
int handle_client_authentication(string pwd_for_keys){
    /*************************************************************
     * M1 - R1 and Username
     *************************************************************/
    int ret;
    uchar* R1 = (uchar*)malloc(NONCE_SIZE);
    if(!R1){
        errorHandler(MALLOC_ERR);
        return -1;
    }

    ret = recv(comm_socket_id, (void *)R1, NONCE_SIZE, 0);
    if (ret <= 0 || ret != NONCE_SIZE){
        errorHandler(REC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
    }
    log("M1 auth (0) Received R1: ");
    BIO_dump_fp(stdout, (const char*)R1, NONCE_SIZE);

    uint32_t client_username_len;
    ret = recv(comm_socket_id, (void *)&client_username_len, sizeof(uint32_t), 0);
    if (ret <= 0 || ret != sizeof(uint32_t)){
        errorHandler(REC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
    }
    client_username_len = ntohl(client_username_len);
    log("M1 auth (1) Received username size: " + to_string(client_username_len));

    char* username = (char*)malloc(client_username_len); //TODO: control size
    if(!username){
        errorHandler(MALLOC_ERR);
        safe_free(R1, NONCE_SIZE);
        return -1;
    }

    ret = recv(comm_socket_id, (void *)username, client_username_len, 0);
    if (ret <= 0 || ret != client_username_len){
        errorHandler(REC_ERR);
        safe_free((uchar*)username, client_username_len);
        safe_free(R1, NONCE_SIZE);
        return -1;
    }
    string client_username(username);
    log("M1 auth (2) Received username: " + client_username);

    ret = set_user_socket(client_username, comm_socket_id); //to test the client
    if(ret != 1){
        cerr << "User not exist!" << endl;
        safe_free((uchar*)username, client_username_len);
        safe_free(R1, NONCE_SIZE);
        return -1;
    }

    safe_free((uchar*)username, client_username_len);

    /*************************************************************
     * M2 - Send R2,pubkey_eph,signature,certificate
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

    //Get certificate of Server
    FILE* cert_file = fopen("certification/SecureCom_cert.pem", "rb"); //TODO: Maybe it's wrong this file
    if(!cert_file){
        log("Error on opening cert file");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }
    
    uchar* certificate_ser;
    uint certificate_len = serialize_certificate(cert_file, &certificate_ser);
    if(certificate_len == 0){
        log("Error on serialize certificate");
        fclose(cert_file);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        return -1;
    }
    log("auth (3) certificate: ");
    BIO_dump_fp(stdout, (const char*)certificate_ser, certificate_len);

    uint M2_to_sign_length = (NONCE_SIZE*2) + eph_pubkey_s_len, M2_signed_length;
    uchar* M2_signed;
    uchar* M2_to_sign = (uchar*)malloc(M2_to_sign_length);
    if(!M2_to_sign){
        log("Error on M2_to_sign");
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        fclose(cert_file);
        return -1;
    }

    memcpy(M2_to_sign, R1, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + NONCE_SIZE), R2, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + (2*NONCE_SIZE)), eph_pubkey_s, eph_pubkey_s_len);
    log("auth (4) M2_to_sign: ");
    BIO_dump_fp(stdout, (const char*)M2_to_sign, M2_to_sign_length);


    ret = sign_document(M2_to_sign, M2_to_sign_length, server_privk,&M2_signed, &M2_signed_length);
    if(ret != 1){
        log("Error on signing part on M2");
        safe_free(M2_to_sign, M2_to_sign_length);
        safe_free(R1, NONCE_SIZE);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_s, eph_pubkey_s_len);
        fclose(cert_file);
        return -1;
    }
    //Send M2 part by part
    
    uint M2_size = NONCE_SIZE + 3*sizeof(uint) + eph_pubkey_s_len + M2_signed_length + certificate_len;
    uint offset = 0;
    uchar* M2 = (uchar*)malloc(M2_size);
    uint eph_pubkey_s_len_net = htonl(eph_pubkey_s_len);
    uint M2_signed_length_net = htonl(M2_signed_length);
    uint certificate_len_net = htonl(certificate_len);
    log("Copying");
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
    memcpy((void*)(M2 + offset), &certificate_len_net ,sizeof(uint));
    offset += sizeof(uint);
    log(to_string(offset));
    memcpy((void*)(M2 + offset), certificate_ser, certificate_len);
    offset += certificate_len;
    log(to_string(offset));

    log("M2 size: " + to_string(M2_size));
    
    ret = send(comm_socket_id, M2, M2_size, 0);
    if(ret < M2_size){
        errorHandler(SEND_ERR);
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
    ret = recv(comm_socket_id, &eph_pubkey_c_len, sizeof(uint32_t), 0);
    if(ret <= 0 || ret != sizeof(uint32_t)){
        errorHandler(REC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        return -1;
    }
    
    eph_pubkey_c_len = ntohl(eph_pubkey_c_len);
    //eph_pubkey_c_len =178;
    log("M3 auth (1) pubkey_c_len: "+ to_string(eph_pubkey_c_len));

    uchar* eph_pubkey_c = (uchar*)malloc(eph_pubkey_c_len);
    if(!eph_pubkey_c ){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        return -1;
    }

    ret = recv(comm_socket_id, eph_pubkey_c, eph_pubkey_c_len, 0);
    if(ret <= 0){
        errorHandler(REC_ERR);
        free(R2);
        free(eph_pubkey_c);
        return -1;
    }
    log("M3 auth (2) pubkey_c:");
    BIO_dump_fp(stdout, (const char*)eph_pubkey_c, eph_pubkey_c_len);

    uint32_t m3_signature_len;
    ret = recv(comm_socket_id, &m3_signature_len, sizeof(uint32_t), 0);
    if(ret <= 0){
        errorHandler(REC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        return -1;
    }
    m3_signature_len = ntohl(m3_signature_len);
    log("M3 auth (3) m3_signature_len: "+ to_string(m3_signature_len));

    uchar* M3_signed = (uchar*)malloc(m3_signature_len); //TODO: control tainted
    if(!M3_signed){
        errorHandler(MALLOC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        return -1;
    }
    ret = recv(comm_socket_id, M3_signed, m3_signature_len, 0);
    if(ret <= 0){
        errorHandler(REC_ERR);
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;
    }

    log("auth (4) M3 signed:");
    BIO_dump_fp(stdout, (const char*)M3_signed, m3_signature_len);

    string pubkey_of_client_path = "certification/" + client_username + "_pubkey.pem";
    FILE* pubkey_of_client = fopen(pubkey_of_client_path.c_str(), "rb");
    if(!pubkey_of_client){
        log("Unable to open pubkey of client");
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
        fclose(pubkey_of_client);
        return -1;
    }

    memcpy(m3_document, eph_pubkey_c,eph_pubkey_c_len );
    memcpy(m3_document+eph_pubkey_c_len, R2, NONCE_SIZE);
    log("auth (5) M3, verifying sign");
    ret = verify_sign_pubkey(M3_signed, m3_signature_len,m3_document,m3_document_size, pubkey_of_client);
    if(ret == 0){
        log("Failed sign verification on M3");
        safe_free(R2, NONCE_SIZE);
        safe_free_privkey(eph_privkey_s);
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        fclose(pubkey_of_client);
        return -1;
    }
    fclose(pubkey_of_client);
    uchar* shared_seceret;
    uint shared_seceret_len;
    log("auth (6) Creating session key");
    shared_seceret_len = derive_secret(eph_privkey_s, eph_pubkey_c, eph_pubkey_c_len, &shared_seceret);
    if(shared_seceret_len == 0){
        log("Failed derive secret");
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        return -1;    
    }
    log("Shared Secret!");
    BIO_dump_fp(stdout, (const char*) shared_seceret, shared_seceret_len);
    session_key_len=default_digest(shared_seceret, shared_seceret_len, &session_key);
    if(session_key_len == 0){
        log("Failed digest computation of the secret");
        safe_free(eph_pubkey_c, eph_pubkey_c_len);
        safe_free(M3_signed, m3_signature_len);
        safe_free(shared_seceret, shared_seceret_len);
        return -1;    
    }
    log("Session key generated!");
    BIO_dump_fp(stdout, (const char*) session_key, session_key_len);
    safe_free(eph_pubkey_c, eph_pubkey_c_len);
    safe_free(M3_signed, m3_signature_len);
    safe_free(shared_seceret, shared_seceret_len);
    //Send user id of the client 
    int client_user_id = get_user_id_by_username(client_username);
    int client_user_id_net = htonl(client_user_id);
    log("Found username in the datastore with user_id " + to_string(client_user_id_net));


    /*ret = send(comm_socket_id, (void*)&client_user_id_net, sizeof(int),0);
    if(ret < sizeof(int)){
        errorHandler(SEND_ERR);
    }
    log("Sent to client: ");
    BIO_dump_fp(stdout, (const char*)&client_user_id, ret);*/
    
    //Prova per send_secure
    
    uchar* userID_msg=(uchar*)malloc(5);
    *userID_msg=USRID;
    memcpy(userID_msg+1, &client_user_id_net,4);
    ret = send_secure(comm_socket_id, userID_msg, sizeof(int)+1);
    if(ret == 0){
        log("Error on send secure");
        return -1;
    }


    //Check if present in the user_datastore
    free(username);
    return get_user_id_by_username(client_username);
}




// ---------------------------------------------------------------------
// FUNCTIONS of HANDLING REPLIES FOR CLIENTS
// ---------------------------------------------------------------------

/**
 *  Handle the response to the client for the !users_online command
 *  @return 0 in case of success, -1 in case of error
 */
int handle_get_online_users(int comm_socket_id, uchar* plaintext){
    log("\n\n*** USERS_ONLINE opcode arrived ***\n");
    int ret;
    uint offset_reply = 0; 
    unsigned char online_cmd = ONLINE_CMD;
    user_info* user_datastore_copy = get_user_datastore_copy();
    vlog("Obtained user datastore copy");

    //Need to calculate how much space to allocate and send (strings have variable length fields)
    int total_space_to_allocate = 9; //TODO: control this number
    int online_users = 0; //also num_pairs
    
    for(int i=0; i<REGISTERED_USERS; i++){
        //Count only online users
        if(user_datastore_copy[i].socket_id != -1){
            total_space_to_allocate += user_datastore_copy[i].username.length() + 8;
            online_users++;
        }
    }

    vlog("Calculated reply size (pt): " + to_string(total_space_to_allocate));
    
    //Copy various fields in the reply msg
    uchar* replyToSend = (uchar*)malloc(total_space_to_allocate);
    if(!replyToSend)
        errorHandler(MALLOC_ERR);
    uint32_t online_users_to_send = htonl(online_users);
    
    //Copy OPCODE and NUM_PAIRS
    memcpy(replyToSend+offset_reply, (void*)&online_cmd, sizeof(uchar));
    offset_reply += sizeof(uchar);
    memcpy(replyToSend+offset_reply, (void*)&online_users_to_send, sizeof(int));
    offset_reply += sizeof(int);

    for(int i=0; i<REGISTERED_USERS; i++){

        //Copy ID, USERNAME_LENGTH and USERNAME for online users
        if(user_datastore_copy[i].socket_id != -1){
            int curr_username_length = user_datastore_copy[i].username.length();
            uint32_t i_to_send = htonl(i);
            uint32_t curr_username_length_to_send = htonl(curr_username_length);
            
            memcpy(replyToSend + offset_reply, (void*)&i_to_send, sizeof(int));
            offset_reply += sizeof(int);
            memcpy(replyToSend + offset_reply, (void*)&curr_username_length_to_send, sizeof(int));
            offset_reply += sizeof(int);
            memcpy(replyToSend + offset_reply, (void*)user_datastore_copy[i].username.c_str(), curr_username_length);
            offset_reply += curr_username_length;
        }
    }
    log("Offset reply: " + to_string(offset_reply));
    ret = send_secure(comm_socket_id, (uchar*)replyToSend, offset_reply);
    if(ret == 0){
        safe_free(replyToSend, total_space_to_allocate);
        safe_free((uchar*)user_datastore_copy, REGISTERED_USERS*sizeof(user_info));
        errorHandler(SEND_ERR);
        return -1;
    }

    // log("Sent to client (pt): ");
    // BIO_dump_fp(stdout, (const char*)replyToSend, ret);
        
    safe_free(replyToSend, total_space_to_allocate);
    safe_free((uchar*)user_datastore_copy, REGISTERED_USERS*sizeof(user_info));
    return 0;    
}



/**
 *  @brief Handle the response to the client for the !chat command
 *  @return 0 in case of success, -1 in case of error
 */
int handle_chat_request(int comm_socket_id, int client_user_id, msg_to_relay& relay_msg, uchar* plaintext){
    log("\n\n*** CHAT opcode arrived ***\n");
    uint offset_plaintext = 5; //From where data is good to read 
    uint offset_relay = 0;
    int ret;

    int peer_user_id_net;
    memcpy(&peer_user_id_net,(const void*)(plaintext + offset_plaintext),sizeof(int));
    offset_plaintext += sizeof(int);
    int peer_user_id = ntohl(peer_user_id_net);

    unsigned char chat_cmd = CHAT_CMD;
    string client_username = get_username_by_user_id(client_user_id);
    int client_username_length = client_username.length();
    uint32_t client_username_length_net = htonl(client_username_length);
    uint32_t client_user_id_net = htonl(client_user_id);
    const char* username = client_username.c_str();
    log(username);
    log("Request for chatting with user id " +  to_string(peer_user_id) + " arrived ");
    // log("Username length is " + to_string(client_username_length) + " net: " + to_string(client_username_length_net));

    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&chat_cmd, 1);
    offset_relay += sizeof(uchar);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&client_user_id_net, sizeof(int));
    offset_relay += sizeof(int);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&client_username_length_net, sizeof(int));
    offset_relay += sizeof(int);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)username, client_username_length);
    offset_relay += client_username_length;

    string pubkey_of_client_path = "certification/" + client_username + "_pubkey.pem";
    log("Opening " + pubkey_of_client_path);
    FILE* pubkey_of_client_file = fopen(pubkey_of_client_path.c_str(), "rb");
    if(!pubkey_of_client_file){
        log("Unable to open pubkey of client");
        return -1;
    }
    uchar* pubkey_client_ser;
    int pubkey_client_ser_len = serialize_pubkey_from_file(pubkey_of_client_file, &pubkey_client_ser);
    log("Pubkey ser len : " + to_string(pubkey_client_ser_len) + "(default: " + to_string(PUBKEY_DEFAULT_SER) + "), pubkey_ser:");
    BIO_dump_fp(stdout, (const char*)pubkey_client_ser, pubkey_client_ser_len);

    // memcpy((void*)(relay_msg.buffer + offset_relay), &pubkey_client_ser_len, sizeof(int));
    // offset_relay += sizeof(int);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)pubkey_client_ser, pubkey_client_ser_len);
    offset_relay += pubkey_client_ser_len;
    
    uint8_t opcode = relay_msg.buffer[0];

    int final_response_len;
    if(opcode == CHAT_NEG)
        final_response_len = 5;
    else
        final_response_len = 5 + PUBKEY_DEFAULT_SER;
    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, offset_relay);    
    //If no other request of notification send the message to the other process through his message queue
    vlog("Handle chat request (2)");
    relay_write(peer_user_id, relay_msg);

    //Wait for response to the own named message queue (blocking)
    vlog("Handle chat request (3)");
    relay_read(client_user_id, relay_msg, true);

    memcpy((void*)(relay_msg.buffer + 1), (void*)&peer_user_id, sizeof(int));    

    
    vlog("Handle chat request (4)");
    // Send reply of the peer to the client
    ret = send_secure(comm_socket_id, (uchar*)relay_msg.buffer, final_response_len);
    if(ret == 0){
        errorHandler(SEND_ERR);
        return -1;
    }
    return 0;    
}


/**
 * @brief handle CHAT_POS and CHAT_NEG commands
 * @return -1 in case of errors, 0 in case of success
 */
int handle_chat_pos_neg(uchar* plaintext, uint8_t opcode){
    if(opcode == CHAT_POS)
        log("\n\n*** Received CHAT_POS command ***\n");
    else if(opcode == CHAT_NEG)
        log("\n\n*** Received CHAT_NEG command ***\n");
    else if(opcode == STOP_CHAT)
        log("\n\n*** Received STOP_CHAT command ***\n");
        
    
    uint offset_plaintext = 5;
    uint offset_relay = 0;
    int peer_user_id_net = *(int*)(plaintext + offset_plaintext);
    offset_plaintext += sizeof(int);
    // int peer_user_id;
    // int peer_user_id_net;
    // int ret = recv(comm_socket_id, (void *)&peer_user_id_net, sizeof(int), 0);
    // if (ret < 0)
    //     errorHandler(REC_ERR);
    // if (ret == 0){
    //     vlog("No message from the server");
    //     exit(1);
    // }

    int peer_user_id = ntohl(peer_user_id_net);
    
    log("Command to send for user_id " +  to_string(peer_user_id) + " arrived ");
    

    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&opcode, sizeof(uchar));
    offset_relay += sizeof(uchar);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&peer_user_id_net, sizeof(int));
    offset_relay += sizeof(int);
    if(opcode == CHAT_POS){
        string client_username = get_username_by_user_id(client_user_id);
        string pubkey_of_client_path = "certification/" + client_username + "_pubkey.pem";
        log("Opening " + pubkey_of_client_path);
        FILE* pubkey_of_client_file = fopen(pubkey_of_client_path.c_str(), "rb");
        if(!pubkey_of_client_file){
            log("Unable to open pubkey of client");
            return -1;
        }
        //Adding pubkey
        //TODO: need to serialize certificate from file;
        uchar* pubkey_client_ser;
        int pubkey_client_ser_len = serialize_pubkey_from_file(pubkey_of_client_file, &pubkey_client_ser);
        log("Pubkey ser len : " + to_string(pubkey_client_ser_len) + "(default: " + to_string(PUBKEY_DEFAULT_SER) + "), pubkey_client_ser:");
        BIO_dump_fp(stdout, (const char*)pubkey_client_ser, pubkey_client_ser_len);

        // memcpy((void*)(relay_msg.buffer + offset_relay), &pubkey_client_ser_len, sizeof(int));
        // offset_relay += sizeof(int);
        memcpy((void*)(relay_msg.buffer + offset_relay), (void*)pubkey_client_ser, PUBKEY_DEFAULT_SER);
        offset_relay += pubkey_client_ser_len;
    }
    
    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, offset_relay);
    relay_write(peer_user_id, relay_msg);
    return 0;
}

int handle_auth_and_msg(uchar* plaintext, uint8_t opcode, int plaintext_len){
    if(opcode == AUTH)
        log("\n\n Arrived AUTH (" + to_string(opcode) + ") command\n\n");
    else if(opcode == CHAT_RESPONSE) 
        log("\n\n Arrived CHAT_RESPONSE command\n\n");

    uint offset_plaintext = 5;
    uint offset_relay = 0;
    int plain_len_without_seq = plaintext_len - 4;
    int peer_user_id_net = *(int*)(plaintext + offset_plaintext);
    offset_plaintext += sizeof(int);
    int peer_user_id = ntohl(peer_user_id_net);
    
    log("Command to send for user_id " +  to_string(peer_user_id) + " arrived ");
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&opcode, sizeof(uint8_t));
    offset_relay += sizeof(uint8_t);
    //Add length of msg in between
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)&plain_len_without_seq, sizeof(int));
    offset_relay += sizeof(int);
    memcpy((void*)(relay_msg.buffer + offset_relay), (void*)(plaintext + 5), plaintext_len - 5);
    offset_relay += (plaintext_len - 5);
    log("plain_len_without_seq: " + to_string(plain_len_without_seq));
    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, offset_relay);
    relay_write(peer_user_id, relay_msg);
    return 0;
}

// /**
//  * @brief Handle CHAT command by sending it to the proper server process of the peer
//  * @return -1 in case of errors, 0 otherwise 
//  */
// int handle_msg(uchar* plaintext, int plaintext_len){
//     log("\n\n *** Received MSG command ***\n");
//     uint offset_plaintext = 5;
//     uint offset_relay
//     unsigned char cmd = CHAT_RESPONSE;
//     int peer_user_id_net = *(int*)(plaintext + offset_plaintext);
//     offset_plaintext += sizeof(int);
//     int peer_user_id = ntohl(peer_user_id_net);
//     memcpy((void*)(relay_msg.buffer), (void*)(plaintext + 4), plaintext_len - 4); //To skip the sequence number

//     // uint16_t peer_user_id_net, msg_length_net;
    
//     // memcpy(&peer_user_id_net, (void*)(plaintext + offset_plaintext), sizeof(uint16_t));
//     // offset_plaintext += sizeof(uint16_t);
//     // memcpy(&msg_length_net, (void*)(plaintext + offset_plaintext), sizeof(uint16_t));
//     // offset_plaintext += sizeof(uint16_t);
//     // char* msg;
//     // int ret = recv(comm_socket_id, (void *)&peer_user_id_net, sizeof(uint16_t), 0);
//     // if (ret < 0)
//     //     errorHandler(REC_ERR);
//     // if (ret == 0){
//     //     vlog("No message from the server");
//     //     exit(1);
//     // }
//     // ret = recv(comm_socket_id, (void *)&msg_length_net, sizeof(uint16_t), 0);
//     // if (ret < 0)
//     //     errorHandler(REC_ERR);
//     // if (ret == 0){
//     //     vlog("No message from the server");
//     //     exit(1);
//     // }

//     uint16_t peer_user_id = ntohs(peer_user_id_net);
//     uint16_t msg_length = ntohs(msg_length_net);

//     log("Peer user id: " + to_string(peer_user_id) + ", msg_length: " + to_string(msg_length));
//     msg = (char*)malloc(msg_length);
//     if(!msg)
//         errorHandler(MALLOC_ERR);
//     memcpy(msg, (void*)(plaintext + offset_plaintext), msg_length);
//     offset_plaintext += msg_length;

//     log("MSG to send for " +  to_string(peer_user_id) + " arrived ");

//     int bytes_offset = 0;
//     memcpy((void*)relay_msg.buffer, (void*)&cmd, sizeof(uint8_t));
//     bytes_offset += sizeof(uint8_t);
//     memcpy((void*)(relay_msg.buffer + bytes_offset), (void*)&peer_user_id_net, sizeof(uint16_t));
//     bytes_offset += sizeof(uint16_t);
//     memcpy((void*)(relay_msg.buffer + bytes_offset), (void*)&msg_length_net, sizeof(uint16_t));
//     bytes_offset += sizeof(uint16_t);
//     memcpy((void*)(relay_msg.buffer + bytes_offset), (void*)msg, msg_length);
//     bytes_offset += msg_length;

//     log("Relaying: ");
//     BIO_dump_fp(stdout, relay_msg.buffer, bytes_offset);

//     relay_write(peer_user_id, relay_msg);
//     return 0;
// }



int main(){
    //Create shared memory for mantaining info about users
    prior_cleanup();
    
    
    if(shmem == MAP_FAILED)
        errorHandler(GEN_ERR);
    user_info user_status[REGISTERED_USERS];
    initialize_user_info(user_status);
    memcpy(shmem, user_status, sizeof(user_info)*REGISTERED_USERS);
    

    int ret;
    int listen_socket_id;   //socket indexes
    struct sockaddr_in srv_addr, cl_addr;   //address informations
    pid_t pid;                              
    string password_for_keys;

    // WE MAY WANT TO DISABLE ECHO
    cout << "Enter the password that will be used for reading the keys: ";
    FILE* server_key = fopen("certification/SecureCom_prvkey.pem", "rb");
    server_privk=read_privkey(server_key, NULL);
    if(!server_privk){
        cerr << "Wrong key!";
        exit(1);
    }

    //Preparation of ip address struct
    memset(&srv_addr, 0, sizeof(srv_addr));
    listen_socket_id = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket_id == -1)
        errorHandler(SOCK_ERR);

    //For avoiding annoying Address already in use error 
    int option = 1;
    setsockopt(listen_socket_id, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    //Configuration of server address
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    inet_pton(AF_INET, srv_ipv4, &srv_addr.sin_addr);
    log("address struct preparation...");

    if (-1 == bind(listen_socket_id, (struct sockaddr *)&srv_addr, sizeof(srv_addr))){
        perror(strerror(errno));
        errorHandler(BIND_ERR);
    }
        
    if (-1 == listen(listen_socket_id, SOCKET_QUEUE))
        errorHandler(LISTEN_ERR);

    unsigned int len = sizeof(cl_addr);
    log("Socket is listening...");

    while (true)
    {
        comm_socket_id = accept(listen_socket_id, (struct sockaddr *)&cl_addr, &len);
        pid = fork();

        if (pid == 0){
            close(listen_socket_id);
            log("Connection established with client");

            //Manage authentication
            client_user_id = handle_client_authentication(password_for_keys);
            if(client_user_id == -1){
                errorHandler(AUTHENTICATION_ERR);
                log("Errore di autenticazione");
                return -1;
            }

            // Every REQUEST_CONTROL_TIME seconds a signal is issued to control if the server has sent
            // a chat request originated from another clientS 
            signal(SIGALRM, signal_handler);
            alarm(RELAY_CONTROL_TIME);

            //Child process
            while (true){
                uchar msgOpcode;
                uchar* plaintext;
                uint plain_len;
                plain_len = recv_secure(comm_socket_id, &plaintext);
                if(plain_len == 0){
                    errorHandler(REC_ERR);
                    return -1;
                }
                msgOpcode = *(uchar*)(plaintext+4);
                log("msgOpcode: " + to_string(msgOpcode));
                
                //Demultiplexing of opcode
                switch (msgOpcode){
                case ONLINE_CMD:
                    ret = handle_get_online_users(comm_socket_id, plaintext);
                    if(ret<0) {
                        log("Error on handle_get_online_users");
                        return 0;
                    }
                    break;

                case CHAT_CMD:
                    ret = handle_chat_request(comm_socket_id, client_user_id, relay_msg, plaintext);
                    if(ret<0) {
                        log("Error on handle_chat_request");
                        return 0;
                    }
                    break;
                
                case CHAT_POS: 
                case CHAT_NEG:
                case STOP_CHAT:
                    ret = handle_chat_pos_neg(plaintext, msgOpcode);
                    if(ret<0) {
                        log("Error on handle_chat_pos_neg");
                        return 0;
                    }
                    break;
                case CHAT_RESPONSE:
                case AUTH:
                    ret = handle_auth_and_msg(plaintext, msgOpcode, plain_len);
                    if(ret<0) {
                        log("Error on handle_msg");
                        return 0;
                    }
                    break;
                default:
                    cout << "Command Not Valid" << endl;
                    break;
                }

            }
        }
        else if (pid == -1){
            errorHandler(FORK_ERR);
            return 0;
        }

        close(comm_socket_id);
    }
}