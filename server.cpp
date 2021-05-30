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
    if(ret != -1){
        // log("ret: " + to_string(ret));   
        log("Received from relay a msg: ");
        BIO_dump_fp(stdout, (const char*)msg.buffer, sizeof(msg_to_relay));
    } else {
        log("read nothing");
    }

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
    log("Received signal for relay_reads");
    int ret;
    uint8_t opcode;

                
    if(relay_read(client_user_id, relay_msg, false) != -1){
        opcode = *relay_msg.buffer;
        log("Found request to relay with opcode: " + to_string(opcode));
        
        if(opcode == CHAT_CMD) {
            int username_length;
            memcpy(&username_length, (void*)(relay_msg.buffer + 5), sizeof(int));
            log("USERNAME LENGTH: " + to_string(username_length));

            int msg_length = 9 + username_length;

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
        } else if(opcode == MSG){
            int msg_length;
            memcpy(&msg_length, (void*)(relay_msg.buffer + 5), sizeof(int));
            log("MSG LENGTH: " + msg_length);
            msg_length += 9;
            // Send reply of the peer to the client
            ret = send(comm_socket_id, relay_msg.buffer, msg_length, 0);
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
// FUNCTIONS of HANDLING REPLIES FOR CLIENTS
// ---------------------------------------------------------------------

/**
 *  Handle the response to the client for the !users_online command
 *  @return 0 in case of success, -1 in case of error
 */
int handle_get_online_users(int comm_socket_id){
    log("USERS_ONLINE opcode arrived");
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
    log("CHAT opcode arrived");
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
    // uint32_t client_username_length_net = htonl(client_username_length);
    // uint32_t client_user_id_net = htonl(client_user_id);
    int final_response_length = 5; //TODO: temporary
    const char* username = client_username.c_str();
    log(username);

    
    log("Request for chatting with user id " +  to_string(peer_user_id) + " arrived ");
    // log("Username length is " + to_string(client_username_length) + " net: " + to_string(client_username_length_net));

    //TODO: add sequence number
    memcpy((void*)relay_msg.buffer, (void*)&chat_cmd, 1);

    // PROPOSTA MODIFICA: stessa cosa commentata a riga 438
    //client_user_id= htonl(client_user_id);
    memcpy((void*)(relay_msg.buffer + 1), (void*)&client_user_id, sizeof(int));
    memcpy((void*)(relay_msg.buffer + 5), (void*)&client_username_length, sizeof(int));
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
    log("Received CHAT_POS command");
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
    memcpy((void*)(relay_msg.buffer + 1), (void*)&peer_user_id, sizeof(int));
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
    
    log("\n\n... WORK IN PROGRESS ...\n\n");
    return 0;
}


int handle_chat_neg(){
    log("Received CHAT_NEG command");
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
    memcpy((void*)(relay_msg.buffer + 1), (void*)&peer_user_id, sizeof(int));
    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, 5);

    relay_write(peer_user_id, relay_msg);
    return 0;
}

int handle_msg(){
    log("Received CHAT command");
    unsigned char cmd = MSG;
    int peer_user_id, msg_length;
    int peer_user_id_net, msg_length_net;
    char* msg;
    int ret = recv(comm_socket_id, (void *)&peer_user_id_net, sizeof(int), 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }
    ret = recv(comm_socket_id, (void *)&msg_length_net, sizeof(int), 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }

    peer_user_id = ntohl(peer_user_id_net);
    msg_length = ntohl(msg_length_net);
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

    memcpy((void*)relay_msg.buffer, (void*)&cmd, 1);
    memcpy((void*)(relay_msg.buffer + 1), (void*)&peer_user_id_net, sizeof(int));
    memcpy((void*)(relay_msg.buffer + 5), (void*)&msg_length_net, sizeof(int));
    memcpy((void*)(relay_msg.buffer + 9), (void*)msg, msg_length);
    log("Relaying: ");
    BIO_dump_fp(stdout, relay_msg.buffer, 9 + msg_length);

    relay_write(peer_user_id, relay_msg);
    return 0;
}

/**
 * @brief handle authentication with the client
 * @return user_id of the client or -1 if not present in the user store or in case of errors
 */
int handle_client_authentication(){
    // RECEIVING M1
    int ret;
    uint16_t R1;
    // ret = recv(comm_socket_id, (void *)&R1, sizeof(NUANCE_DEFAULT), 0);
    // if (ret < 0)
    //     errorHandler(REC_ERR);
    // if (ret == 0){
    //     vlog("No message from the server");
    //     exit(1);
    // }
    // R1 = ntohl(R1);

    uint16_t size;
    ret = recv(comm_socket_id, (void *)&size, sizeof(uint16_t), 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }

    size = ntohs(size);
    log("Received username size: " + to_string(size));
    char* username = (char*)malloc(sizeof(char)*size);
    if(!username)
        errorHandler(MALLOC_ERR);

    ret = recv(comm_socket_id, (void *)username, size, 0);
    if (ret < 0)
        errorHandler(REC_ERR);
    if (ret == 0){
        vlog("No message from the server");
        exit(1);
    }
    
    string client_username(username);
    log("Received username: " + client_username);
    
    ret = set_user_socket(client_username, comm_socket_id); //to test the client
    if(ret != 1){
        cerr << "User not exist!" << endl;
        free(username);
        exit(1);
    }


    // PREPARING M2
    uchar* R2 = (uchar*)malloc(NUANCE_DEFAULT);
    if(!R2){
        errorHandler(MALLOC_ERR);
    }


    //Generate pair of ephermeral DH keys
    void* eph_privkey_s;
    uchar* eph_pubkey_s;
    uint pubkey_len = PUBKEY_DEFAULT;
    ret = eph_key_generate(&eph_privkey_s, &eph_pubkey_s, &pubkey_len);
    if(ret != 1){
        log("Error on EPH_KEY_GENERATE");
        exit(1);
    }

    //Generate nuance R2
    ret = random_generate(NUANCE_DEFAULT, R2);
    if(ret != 1){
        log("Error on random_generate");
        exit(1);
    }
    log("auth (2) R2: ");
    BIO_dump_fp(stdout, (const char*)R2, NUANCE_DEFAULT);

    //Get certificate of Server
    FILE* cert_file = fopen("certification/SecureCom_cert.pem", "rb");
    if(!cert_file){
        log("Error on opening cert file");
        exit(1);
    }
    
    uchar* certificate_ser;
    ret = serialize_certificate(cert_file, &certificate_ser);
    if(ret == 0){
        log("Error on serialize certificate");
    }

    uint M2_to_sign_length = NUANCE_DEFAULT*2 + PUBKEY_DEFAULT, M2_signed_length;
    uchar* M2_to_sign = (uchar*)malloc(M2_to_sign_length);
    uchar* M2_signed;
    if(!M2_to_sign){
        log("Error on M2_to_sign");
        exit(1);
    }

    memcpy(M2_to_sign, &R1, sizeof(uint16_t));
    memcpy((void*)(M2_to_sign + 2), &R2, sizeof(uint16_t));
    memcpy((void*)(M2_to_sign + 4), eph_pubkey_s, PUBKEY_DEFAULT);

    FILE* server_key = fopen("certification/SecureCom_key.pem", "rb");
    if(!server_key){
        log("Error on opening key file");
        exit(1);
    }

    ret = sign_document(M2_to_sign, M2_to_sign_length, server_key,&M2_signed, &M2_signed_length);
    if(ret != 1){
        log("Error on signing part on M2");
        exit(1);
    }

    //Send M2 part by part
    // ret = send(comm_socket_id, eph_pubkey_s, PUBKEY_DEFAULT, 0);
    // if(ret <= PUBKEY_DEFAULT){
    //     errorHandler(SEND_ERR);
    //     exit(1);
    // }    
    // ret = send(comm_socket_id, &R2, NUANCE_DEFAULT, 0);
    // if(ret <= NUANCE_DEFAULT){
    //     errorHandler(SEND_ERR);
    //     exit(1);
    // }
    // ret = send(comm_socket_id, M2_signed, M2_signed_length, 0);
    // if(ret <= M2_signed_length){
    //     errorHandler(SEND_ERR);
    //     exit(1);
    // }
    // ret = send(comm_socket_id, certificate_ser,);
    // if(ret <= ){
    //     errorHandler(SEND_ERR);
    //     exit(1);
    // }



    //Receiving M3
    // uchar* eph_pubkey_c = (uchar*)malloc(PUBKEY_DEFAULT);
    // if(!eph_pubkey_c){
    //     errorHandler(MALLOC_ERR);
    //     exit(1);
    // }

    // ret = recv(comm_socket_id, eph_pubkey_c, PUBKEY_DEFAULT, 0);
    // if(ret <= 0){
    //     errorHandler(REC_ERR);
    //     exit(1);
    // }

    // //TODO: need to know certificate length for M2 and M3
    // uchar* M3_signed = (uchar*)malloc(...);
    // if(!M3_signed){
    //     errorHandler(MALLOC_ERR);
    //     exit(1);
    // }
    // ret = recv(comm_socket_id, M3_signed, ..., 0);
    // if(ret <= 0){
    //     errorHandler(REC_ERR);
    //     exit(1);
    // }

    // verify_sign_pubkey();
    // derive_secret();



    
    //Send user id of the client 
    int client_user_id = get_user_id_by_username(client_username);
    int client_user_id_net = htonl(client_user_id);
    ret = send(comm_socket_id, (void*)&client_user_id_net, sizeof(int),0);
    if(ret < sizeof(int)){
        errorHandler(SEND_ERR);
    }
    log("Sent to client: ");
    BIO_dump_fp(stdout, (const char*)&client_user_id, ret);

    
    //Check if present in the user_datastore
    free(username);
    return get_user_id_by_username(client_username);
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

            /*
            * HANDLE AUTH and UPDATE USER DATA STORE
            */
            client_user_id = handle_client_authentication();
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
                
                /*
                * Control if there is a need to relay by checking if our entry is okay
                */    
                

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
                case MSG:
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