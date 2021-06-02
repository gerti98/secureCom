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

uchar* session_key;
uint32_t session_key_len;

//Handling mutual exclusion for accessing the user datastore
const char* sem_user_store_name = "/user_store";
const char* message_queue_name = "/user_message_queue";

void* create_shared_memory(ssize_t size);

//Shared memory for storing data of users
void* shmem = create_shared_memory(sizeof(user_info)*REGISTERED_USERS);

    
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
}

// ---------------------------------------------------------------------
// FUNCTIONS of INTER-PROCESS COMMUNICATION
// ---------------------------------------------------------------------

/** 
 *  Send message to message queue of to_user_id
 *  @return 0 in case of success, -1 in case of error
 */
int relay_write(int to_user_id, msg_to_relay &msg){
    log("Entering relay_write for " + to_string(to_user_id));

    msg.type = to_user_id + 1;
    
    //Write to the message queue
    key_t key = ftok(message_queue_name, 65); 
    vvlog("Key of ftok returned is " + to_string(key));
    int msgid = msgget(key, 0666 | IPC_CREAT);
    vvlog("msgid is " + to_string(msgid));

    // log("Relaying: ");
    // BIO_dump_fp(stdout, (const char*)msg.buffer, sizeof(msg_to_relay));

    msgsnd(msgid, &msg, sizeof(msg_to_relay), 0);
    return 0;
}

/**
 * @brief read from message queue of user_id (blocking)
 * @return -1 if no message has been read otherwise return the bytes copied
 **/
int relay_read(int user_id, msg_to_relay &msg, bool blocking){
    if(blocking)
        alarm(0);

    int ret = -1;
    log("Entering relay_read of " + to_string(user_id) + "[" + (blocking? "blocking": "no_wait") + "]");

    //Read from the message queue
    key_t key = ftok(message_queue_name, 65); 
    vlog("Key of ftok returned is " + to_string(key));
    msg.type = 0;
    int msgid = msgget(key, 0666 | IPC_CREAT);
    vlog("msgid is " + to_string(msgid));
    
    ret = msgrcv(msgid, &msg, sizeof(msg), user_id+1, (blocking? 0: IPC_NOWAIT));
    if (ret == -1) {
        log("read nothing");
    }

    if(blocking)
        alarm(RELAY_CONTROL_TIME);
    log("HEy");
    
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
    log("Received signal for relay_reads");
    int ret;
    uint8_t opcode;

                
    if(relay_read(client_user_id, relay_msg, false) != -1){
        opcode = *relay_msg.buffer;
        log("Found request to relay with opcode: " + to_string(opcode));
        
        if(opcode == CHAT_CMD) {
            int username_length, username_length_net;
            memcpy(&username_length_net, (void*)(relay_msg.buffer + 5), sizeof(int));
            username_length = ntohl(username_length_net);
            log("USERNAME LENGTH: " + to_string(username_length));

            int msg_length = 9 + username_length; //TODO: not so good to hard code things

            // Send reply of the peer to the client
            ret = send(comm_socket_id, relay_msg.buffer, msg_length, 0);
            if(ret < msg_length)
                errorHandler(SEND_ERR);
            log("Sent to client : ");    
            BIO_dump_fp(stdout, (const char*)relay_msg.buffer, ret);

        } else if(opcode == CHAT_POS || opcode == CHAT_NEG){
            int msg_length = 5;
            ret = send(comm_socket_id, relay_msg.buffer, msg_length, 0);
            if(ret < msg_length)
                errorHandler(SEND_ERR);
            log("Sent to client : ");    
            BIO_dump_fp(stdout, (const char*)relay_msg.buffer, ret);
        } else if(opcode == CHAT_RESPONSE){
            uint16_t msg_length_net, msg_length;
            memcpy(&msg_length_net, (void*)(relay_msg.buffer + 3), sizeof(uint16_t));
            msg_length = ntohs(msg_length_net);
            
            log("MSG LENGTH: " + msg_length);
            uint16_t total_plaintext_len = msg_length + 5;

            // Send reply of the peer to the client
            ret = send(comm_socket_id, relay_msg.buffer, total_plaintext_len, 0);
            if(ret < msg_length)
                errorHandler(SEND_ERR);
            log("Sent to client : ");    
            BIO_dump_fp(stdout, (const char*)relay_msg.buffer, ret);
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



/**
 * @brief perform a an authenticad encryption and then a send operation
 * @return 1 in case of success, 0 in case of error 
 */
int send_secure(int comm_socket_id, uchar* pt, int pt_len){
    int ret;
    uchar *tag, *iv, *ct, *aad;
    int aad_ct_len_net = htonl(pt_len); //Since we use GCM ciphertext == plaintext
    uint aad_len;
    log("Plaintext to send:");
    BIO_dump_fp(stdout, (const char*)pt, pt_len);
    uint32_t header_len = sizeof(uint32_t)+IV_DEFAULT+TAG_DEFAULT;


    int ct_len = auth_enc_encrypt(pt, pt_len, (uchar*)&aad_ct_len_net, sizeof(uint), session_key, &tag, &iv, &ct);
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

    ret = send(comm_socket_id, msg_to_send, msg_to_send_len, 0);
    if(ret <= 0 || ret != msg_to_send_len){
        errorHandler(SEND_ERR);
        free(msg_to_send);
        return 0;
    }
    cout << " DBG - message sent " << endl;
    free(msg_to_send);
    return 1;
}


/**
 * @brief perform a an authenticad decryption and then a send operation
 * @return 1 in case of success, 0 in case of error 
 */
int recv_secure(){
    return 0;
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
        exit(1);
    }

    ret = recv(comm_socket_id, (void *)R1, NONCE_SIZE, 0);
    if (ret <= 0 || ret != NONCE_SIZE){
        errorHandler(REC_ERR);
        exit(1);
    }
    log("M1 auth (0) Received R1: ");
    BIO_dump_fp(stdout, (const char*)R1, NONCE_SIZE);

    uint32_t client_username_len;
    ret = recv(comm_socket_id, (void *)&client_username_len, sizeof(uint32_t), 0);
    if (ret <= 0 || ret != sizeof(uint32_t)){
        errorHandler(REC_ERR);
        exit(1);
    }
    client_username_len = ntohl(client_username_len);
    log("M1 auth (1) Received username size: " + to_string(client_username_len));

    char* username = (char*)malloc(sizeof(char)*client_username_len); //TODO: control size
    if(!username){
        errorHandler(MALLOC_ERR);
        free(R1);
        exit(1);
    }

    ret = recv(comm_socket_id, (void *)username, client_username_len, 0);
    if (ret <= 0 || ret != client_username_len){
        errorHandler(REC_ERR);
        free(username);
        free(R1);
        exit(1);
    }
    string client_username(username);
    log("M1 auth (2) Received username: " + client_username);

    ret = set_user_socket(client_username, comm_socket_id); //to test the client
    if(ret != 1){
        cerr << "User not exist!" << endl;
        free(username);
        free(R1);
        exit(1);
    }

    free(username);

    /*************************************************************
     * M2 - Send R2,pubkey_eph,signature,certificate
     *************************************************************/
    uchar* R2 = (uchar*)malloc(NONCE_SIZE);
    if(!R2){
        errorHandler(MALLOC_ERR);
        free(R1);
        exit(1);
    }

    //Generate pair of ephermeral DH keys
    void* eph_privkey_s;
    uchar* eph_pubkey_s;
    uint eph_pubkey_s_len;
    ret = eph_key_generate(&eph_privkey_s, &eph_pubkey_s, &eph_pubkey_s_len);
    if(ret != 1){
        log("Error on EPH_KEY_GENERATE");
        free(R2);
        free(R1);
        free(eph_privkey_s);
        free(eph_pubkey_s);
        exit(1);
    }
    log("M2 auth (1) pubkey: ");
    BIO_dump_fp(stdout, (const char*)eph_pubkey_s, eph_pubkey_s_len);

    //Generate nuance R2
    ret = random_generate(NONCE_SIZE, R2);
    if(ret != 1){
        log("Error on random_generate");
        free(R2);
        free(R1);
        free(eph_privkey_s);
        free(eph_pubkey_s);
        exit(1);
    }

    log("auth (2) R2: ");
    BIO_dump_fp(stdout, (const char*)R2, NONCE_SIZE);

    //Get certificate of Server
    FILE* cert_file = fopen("certification/SecureCom_cert.pem", "rb"); //TODO: Maybe it's wrong this file
    if(!cert_file){
        log("Error on opening cert file");
        free(R2);
        free(R1);
        free(eph_privkey_s);
        free(eph_pubkey_s);
        exit(1);
    }
    
    uchar* certificate_ser;
    uint certificate_len = serialize_certificate(cert_file, &certificate_ser);
    if(certificate_len == 0){
        log("Error on serialize certificate");
        fclose(cert_file);
        free(R2);
        free(R1);
        free(eph_privkey_s);
        free(eph_pubkey_s);
        exit(1);
    }
    log("auth (3) certificate: ");
    BIO_dump_fp(stdout, (const char*)certificate_ser, certificate_len);

    uint M2_to_sign_length = (NONCE_SIZE*2) + eph_pubkey_s_len, M2_signed_length;
    uchar* M2_signed;
    uchar* M2_to_sign = (uchar*)malloc(M2_to_sign_length);
    if(!M2_to_sign){
        log("Error on M2_to_sign");
        free(R2);
        free(R1);
        free(eph_privkey_s);
        free(eph_pubkey_s);
        exit(1);
    }

    memcpy(M2_to_sign, R1, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + NONCE_SIZE), R2, NONCE_SIZE);
    memcpy((void*)(M2_to_sign + (2*NONCE_SIZE)), eph_pubkey_s, eph_pubkey_s_len);
    log("auth (4) M2_to_sign: ");
    BIO_dump_fp(stdout, (const char*)M2_to_sign, M2_to_sign_length);
    FILE* server_key = fopen("certification/SecureCom_prvkey.pem", "rb"); //TODO: Maybe it's wrong this file
    if(!server_key){
        log("Error on opening key file");
        free(R2);
        free(R1);
        free(M2_to_sign);
        free(eph_privkey_s);
        free(eph_pubkey_s);
        exit(1);
    }

    ret = sign_document(M2_to_sign, M2_to_sign_length, server_key,&M2_signed, &M2_signed_length);
    if(ret != 1){
        log("Error on signing part on M2");
        free(R2);
        free(R1);
        free(M2_to_sign);
        free(eph_privkey_s);
        free(eph_pubkey_s);
        exit(1);
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
        free(R2);
        free(R1);
        free(M2_to_sign);
        free(eph_privkey_s);
        free(eph_pubkey_s);
        exit(1);
    }
    log("M2 sent");
    BIO_dump_fp(stdout, (const char*)M2, offset);

    free(M2);
    free(R1);
    free(M2_to_sign);
    free(eph_pubkey_s);

    /*************************************************************
     * M3 - client_pubkey and signing of pubkey and R2
     *************************************************************/
    uint32_t eph_pubkey_c_len;
    ret = recv(comm_socket_id, &eph_pubkey_c_len, sizeof(uint32_t), 0);
    if(ret <= 0 || ret != sizeof(uint32_t)){
        errorHandler(REC_ERR);
        free(R2);
        exit(1);
    }
    
    eph_pubkey_c_len = ntohl(eph_pubkey_c_len);
    //eph_pubkey_c_len =178;
    log("M3 auth (1) pubkey_c_len: "+ to_string(eph_pubkey_c_len));

    uchar* eph_pubkey_c = (uchar*)malloc(eph_pubkey_c_len);
    if(!eph_pubkey_c ){
        errorHandler(MALLOC_ERR);
        free(R2);
        exit(1);
    }

    ret = recv(comm_socket_id, eph_pubkey_c, eph_pubkey_c_len, 0);
    if(ret <= 0){
        errorHandler(REC_ERR);
        free(R2);
        free(eph_pubkey_c);
        exit(1);
    }
    log("M3 auth (2) pubkey_c:");
    BIO_dump_fp(stdout, (const char*)eph_pubkey_c, eph_pubkey_c_len);

    uint32_t m3_signature_len;
    ret = recv(comm_socket_id, &m3_signature_len, sizeof(uint32_t), 0);
    if(ret <= 0){
        errorHandler(REC_ERR);
        free(R2);
        free(eph_pubkey_c);
        exit(1);
    }
    m3_signature_len = ntohl(m3_signature_len);
    log("M3 auth (3) m3_signature_len: "+ to_string(m3_signature_len));

    uchar* M3_signed = (uchar*)malloc(m3_signature_len); //TODO: control tainted
    if(!M3_signed){
        errorHandler(MALLOC_ERR);
        free(R2);
        free(eph_pubkey_c);
        exit(1);
    }
    ret = recv(comm_socket_id, M3_signed, m3_signature_len, 0);
    if(ret <= 0){
        errorHandler(REC_ERR);
        free(R2);
        free(eph_pubkey_c);
        free(M3_signed);
        exit(1);
    }

    log("auth (4) M3 signed:");
    BIO_dump_fp(stdout, (const char*)M3_signed, m3_signature_len);

    string pubkey_of_client_path = "certification/" + client_username + "_pubkey.pem";
    FILE* pubkey_of_client = fopen(pubkey_of_client_path.c_str(), "rb");
    if(!pubkey_of_client){
        log("Unable to open pubkey of client");
        free(R2);
        free(eph_pubkey_c);
        free(M3_signed);
        exit(1);
    }

    uint m3_document_size = eph_pubkey_c_len + NONCE_SIZE;
    uchar* m3_document = (uchar*)malloc(m3_document_size);
    if(!m3_document){
        errorHandler(MALLOC_ERR);
        free(R2);
        free(eph_pubkey_c);
        free(M3_signed);
        exit(1);
    }

    memcpy(m3_document, eph_pubkey_c,eph_pubkey_c_len );
    memcpy(m3_document+eph_pubkey_c_len, R2, NONCE_SIZE);
    log("auth (5) M3, verifying sign");
    ret = verify_sign_pubkey(M3_signed, m3_signature_len,m3_document,m3_document_size, pubkey_of_client);
    if(ret == 0){
        log("Failed sign verification on M3");
        free(eph_pubkey_c);
        free(M3_signed);
        exit(1);
    }

    log("auth (6) Creating session key");
    session_key_len = derive_secret(eph_privkey_s, eph_pubkey_c, eph_pubkey_c_len, &session_key);
    if(session_key_len == 0){
        log("Failed derive secret");
        free(eph_pubkey_c);
        free(M3_signed);
        exit(1);    
    }

    log("Session key generated!");
    BIO_dump_fp(stdout, (const char*) session_key, session_key_len);
    free(M3_signed);


    //Send user id of the client 
    int client_user_id = get_user_id_by_username(client_username);
    int client_user_id_net = htonl(client_user_id);



    /*ret = send(comm_socket_id, (void*)&client_user_id_net, sizeof(int),0);
    if(ret < sizeof(int)){
        errorHandler(SEND_ERR);
    }
    log("Sent to client: ");
    BIO_dump_fp(stdout, (const char*)&client_user_id, ret);*/
    
    //Prova per send_secure
    
    ret = send_secure(comm_socket_id, (uchar *)&client_user_id_net, sizeof(int));
    if(ret == 0){
        log("Error on send secure");
        exit(1);
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
int handle_get_online_users(int comm_socket_id){
    log("\n\n*** USERS_ONLINE opcode arrived ***\n");
    int ret;
    
    /*
    *   Format of the message to send
    *     COMMAND_CODE | NUM_PAIRS | (USER_INDEX | LENGTH_USERNAME | USERNAME)*
    */

    unsigned char online_cmd = ONLINE_CMD;
    user_info* user_datastore_copy = get_user_datastore_copy();
    vlog("Obtained user datastore copy");

    //Need to calculate how much space to allocate and send (strings have variable length fields)
    int total_space_to_allocate = 5; //
    int online_users = 0; //also num_pairs
    int curr_position = 5; //Offset of the buffer
    
    for(int i=0; i<REGISTERED_USERS; i++){
        //Count only online users
        if(user_datastore_copy[i].socket_id != -1){
            total_space_to_allocate += user_datastore_copy[i].username.length() + 8;
            online_users++;
        }
    }

    vlog("Calculated reply size");
    
    //Copy various fields in the reply msg
    uchar* replyToSend = (uchar*)malloc(total_space_to_allocate);
    if(!replyToSend)
        errorHandler(MALLOC_ERR);
    uint32_t online_users_to_send = htonl(online_users);
    
    //Copy OPCODE and NUM_PAIRS
    memcpy(replyToSend, (void*)&online_cmd, sizeof(unsigned char));
    memcpy(replyToSend+1, (void*)&online_users_to_send, sizeof(int));
    
    for(int i=0; i<REGISTERED_USERS; i++){

        //Copy ID, USERNAME_LENGTH and USERNAME for online users
        if(user_datastore_copy[i].socket_id != -1){
            int curr_username_length = user_datastore_copy[i].username.length();
            uint32_t i_to_send = htonl(i);
            uint32_t curr_username_length_to_send = htonl(curr_username_length);
            
            memcpy(replyToSend + curr_position, (void*)&i_to_send, sizeof(int));
            memcpy(replyToSend + curr_position + 4, (void*)&curr_username_length_to_send, sizeof(int));
            memcpy(replyToSend + curr_position + 8, (void*)user_datastore_copy[i].username.c_str(), curr_username_length);

            curr_position = curr_position + 8 + curr_username_length;
        }
    }

    log("Total length of buffer to send: " + to_string(curr_position));
    
    ret = send(comm_socket_id, replyToSend, total_space_to_allocate, 0);
    if(ret < 0 || ret!=total_space_to_allocate){
        free(replyToSend);
        free(user_datastore_copy);
        errorHandler(SEND_ERR);
    }

    log("Sent to client: ");
    BIO_dump_fp(stdout, (const char*)replyToSend, ret);
        
    free(replyToSend);
    free(user_datastore_copy);
    return 0;    
}


/**
 *  @brief Handle the response to the client for the !chat command
 *  @return 0 in case of success, -1 in case of error
 */
int handle_chat_request(int comm_socket_id, int client_user_id, msg_to_relay& relay_msg){
    log("\n\n*** CHAT opcode arrived ***\n");
    // Consuming the receiving buffer
    int peer_user_id;
    int peer_user_id_net;
    int ret = recv(comm_socket_id, (void *)&peer_user_id_net, sizeof(int), 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }

    peer_user_id = ntohl(peer_user_id_net);
    unsigned char chat_cmd = CHAT_CMD;
    string client_username = get_username_by_user_id(client_user_id);
    int client_username_length = client_username.length();
    uint32_t client_username_length_net = htonl(client_username_length);
    uint32_t client_user_id_net = htonl(client_user_id);
    int final_response_length = 5; //TODO: temporary
    const char* username = client_username.c_str();
    log(username);

    
    log("Request for chatting with user id " +  to_string(peer_user_id) + " arrived ");
    // log("Username length is " + to_string(client_username_length) + " net: " + to_string(client_username_length_net));

    //TODO: add sequence number
    memcpy((void*)relay_msg.buffer, (void*)&chat_cmd, 1);

    // PROPOSTA MODIFICA: stessa cosa commentata a riga 438
    //client_user_id= htonl(client_user_id);
    memcpy((void*)(relay_msg.buffer + 1), (void*)&client_user_id_net, sizeof(int));
    memcpy((void*)(relay_msg.buffer + 5), (void*)&client_username_length_net, sizeof(int));
    memcpy((void*)(relay_msg.buffer + 9), (void*)username, client_username_length);
    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, (9 + client_username_length));
    //TODO: add pubkey

    
    //If no other request of notification send the message to the other process through his message queue
    vlog("Handle chat request (2)");
    relay_write(peer_user_id, relay_msg);

    //Wait for response to the own named message queue (blocking)
    vlog("Handle chat request (3)");
    relay_read(client_user_id, relay_msg, true);

    //TODO: add sequence number
    memcpy((void*)(relay_msg.buffer + 1), (void*)&peer_user_id, sizeof(int));    

    
    vlog("Handle chat request (4)");
    // Send reply of the peer to the client
    ret = send(comm_socket_id, relay_msg.buffer, final_response_length, 0);
    if(ret < 0 || ret!=5)
        errorHandler(SEND_ERR);

    /**
     * 
     *  WAIT FOR SECOND AUTHENTICATION if CHAT_POS has been sent
     * 
    **/

    log("Sent to client: ");    
    BIO_dump_fp(stdout, (const char*)relay_msg.buffer, ret);

    return 0;    
}


int handle_chat_pos(){
    log("\n\n*** Received CHAT_POS command ***\n");
    int peer_user_id;
    int peer_user_id_net;
    int ret = recv(comm_socket_id, (void *)&peer_user_id_net, sizeof(int), 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }

    peer_user_id = ntohl(peer_user_id_net);
    unsigned char chat_cmd = CHAT_POS;
    

    log("Chat Positive to send for " +  to_string(peer_user_id) + " arrived ");
    
    //TODO: sequence number
    memcpy((void*)relay_msg.buffer, (void*)&chat_cmd, 1);
    memcpy((void*)(relay_msg.buffer + 1), (void*)&peer_user_id_net, sizeof(int));
    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, 5);

    //TODO: senderpubkey

    log("handle_chat_pos (2)");
    relay_write(peer_user_id, relay_msg);

    /**
     * 
     *  WAIT FOR SECOND AUTHENTICATION
     * 
    **/
    return 0;
}


int handle_chat_neg(){
    log("\n\n*** Received CHAT_NEG command ***\n");
    int peer_user_id;
    int peer_user_id_net;
    int ret = recv(comm_socket_id, (void *)&peer_user_id_net, sizeof(int), 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }
    peer_user_id = ntohl(peer_user_id_net);
    unsigned char chat_cmd = CHAT_NEG;

    //TODO: sequence number
    log("Chat Negative to send for " +  to_string(peer_user_id) + " arrived ");

    memcpy((void*)relay_msg.buffer, (void*)&chat_cmd, 1);
    memcpy((void*)(relay_msg.buffer + 1), (void*)&peer_user_id_net, sizeof(int));
    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, 5);

    relay_write(peer_user_id, relay_msg);
    return 0;
}


/**
 * @brief Handle CHAT command by sending it to the proper server process of the peer
 * @return 0 in case of errors, 1 otherwise 
 */
int handle_msg(){
    log("\n\n *** Received MSG command ***\n");
    unsigned char cmd = CHAT_RESPONSE;
    uint16_t peer_user_id, msg_length;
    uint16_t peer_user_id_net, msg_length_net;
    char* msg;
    int ret = recv(comm_socket_id, (void *)&peer_user_id_net, sizeof(uint16_t), 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }
    ret = recv(comm_socket_id, (void *)&msg_length_net, sizeof(uint16_t), 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }

    peer_user_id = ntohs(peer_user_id_net);
    msg_length = ntohs(msg_length_net);

    log("Peer user id: " + to_string(peer_user_id) + ", msg_length: " + to_string(msg_length));
    msg = (char*)malloc(msg_length);
    if(!msg)
        errorHandler(MALLOC_ERR);
    ret = recv(comm_socket_id, (void *)msg, msg_length, 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }

     //TODO: sequence number
    log("MSG to send for " +  to_string(peer_user_id) + " arrived ");

    int bytes_offset = 0;
    memcpy((void*)relay_msg.buffer, (void*)&cmd, sizeof(uint8_t));
    bytes_offset += sizeof(uint8_t);
    memcpy((void*)(relay_msg.buffer + bytes_offset), (void*)&peer_user_id_net, sizeof(uint16_t));
    bytes_offset += sizeof(uint16_t);
    memcpy((void*)(relay_msg.buffer + bytes_offset), (void*)&msg_length_net, sizeof(uint16_t));
    bytes_offset += sizeof(uint16_t);
    memcpy((void*)(relay_msg.buffer + bytes_offset), (void*)msg, msg_length);
    bytes_offset += msg_length;

    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, bytes_offset);

    relay_write(peer_user_id, relay_msg);
    return 0;
}



int main()
{
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
    //char send_buffer[1024];                 //buffer for sending replies
    pid_t pid;                              
    string password_for_keys;
    cout << "Enter the password that will be used for reading the keys: ";
    cin >> password_for_keys;

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

        if (pid == 0)
        {

            close(listen_socket_id);
            log("Connection established with client");

            //Manage authentication
            client_user_id = handle_client_authentication(password_for_keys);
            if(client_user_id == -1){
                errorHandler(AUTHENTICATION_ERR);
            }

            // Every REQUEST_CONTROL_TIME seconds a signal is issued to control if the server has sent
            // a chat request originated from another clientS 
            signal(SIGALRM, signal_handler);
            alarm(RELAY_CONTROL_TIME);

            //Child process
            while (true)
            {

                uchar msgOpcode;
 
                //Get Opcode from the client
                ret = recv(comm_socket_id, (void *)&msgOpcode, sizeof(uint8_t), 0);

                if (ret < 0)
                    errorHandler(REC_ERR);
                if (ret == 0){
                    vlog("No message from the server");
                    exit(1);
                }
                //Demultiplexing of opcode
                switch (msgOpcode){
                case CHAT_CMD:
                    ret = handle_chat_request(comm_socket_id, client_user_id, relay_msg);
                    if(ret<0)
                        errorHandler(GEN_ERR);
                    break;

                case ONLINE_CMD:
                    ret = handle_get_online_users(comm_socket_id);
                    if(ret<0)
                        errorHandler(GEN_ERR);
                    break;
                
                case CHAT_POS:
                    ret = handle_chat_pos();
                    if(ret<0)
                        errorHandler(GEN_ERR);
                    break;
                case CHAT_NEG:
                    ret = handle_chat_neg();
                    if(ret<0)
                        errorHandler(GEN_ERR);
                    break;
                case CHAT_RESPONSE:
                    ret = handle_msg();
                    if(ret < 0)
                        errorHandler(MSG_ERR);
                    break;
                default:
                    cout << "Command Not Valid" << endl;
                    break;
                }

            }
        }
        else if (pid == -1)
        {
            errorHandler(FORK_ERR);
        }

        close(comm_socket_id);
    }
}