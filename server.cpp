#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "constant.h"
#include "util.h"

using namespace std;


/*
* socket_id: if equal to -1 the user is not connected to the service
*/
struct user_info {
    string username;
    int socket_id; 
};

const char* sem_user_store_name = "/user_store";

//Parameters of connection
const char *srv_ipv4 = "127.0.0.1";
const int srv_port = 4242;

void* create_shared_memory(ssize_t size);
//Shared memory for storing data of users
void* shmem = create_shared_memory(sizeof(user_info)*REGISTERED_USERS);

void* create_shared_memory(ssize_t size){
    int protection = PROT_READ | PROT_WRITE;
    int visibility = MAP_SHARED | MAP_ANONYMOUS;
    return mmap(NULL, size, protection, visibility, -1, 0);
}

int handle_chat_request(int comm_socket){
    log("Chat request arrived");
    return 0;    
}


int get_online_users(){
    log("Get Online Users request arrived");
    return 0;    
}



/**
 * @return -1: username not present, 0: successfully written socket data
 */
int set_user_socket(string username, int socket){

    sem_t* sem_id= sem_open(sem_user_store_name, O_CREAT, 0600, 1);
    if(sem_id == SEM_FAILED)
        errorHandler(GEN_ERR);
    if(sem_wait(sem_id) < 0)
        errorHandler(GEN_ERR);
    
    user_info* user_status = (user_info*)shmem;
    int found = -1;
    for(int i=0; i<REGISTERED_USERS; i++){
        if(user_status[i].username.compare(username) == 0){
            user_status[i].socket_id = socket;
            log("Set socket of " + username + " correctly");
            found = 0;
            break;
        }
    }

    if(sem_post(sem_id) < 0)
        errorHandler(GEN_ERR);
    if(sem_close(sem_id) < 0)
        errorHandler(GEN_ERR);

    return found;
}


void print_user_data_store(){
    sem_t* sem_id= sem_open(sem_user_store_name, O_CREAT, 0600, 1);
    if(sem_id == SEM_FAILED)
        errorHandler(GEN_ERR);
    if(sem_wait(sem_id) < 0)
        errorHandler(GEN_ERR);

    
    user_info* user_status = (user_info*)shmem;
    cout << "****** USER STATUS *******" << endl;
    for(int i=0; i<REGISTERED_USERS; i++){
        cout << i << ") " << user_status[i].username << "\t" << user_status[i].socket_id << "\t" << ((user_status[i].socket_id==-1)?"offline":"online") << endl;
    }

    if(sem_post(sem_id) < 0)
        errorHandler(GEN_ERR);
    if(sem_close(sem_id) < 0)
        errorHandler(GEN_ERR);
}

void initialize_user_info(user_info* user_status){
    user_status[0].username = "alice";
    user_status[0].socket_id = -1;
    user_status[1].username = "bob";
    user_status[1].socket_id = -1;
    user_status[2].username = "charlie";
    user_status[2].socket_id = -1;
    user_status[3].username = "dave";
    user_status[3].socket_id = -1;
    user_status[4].username = "ethan";
    user_status[4].socket_id = -1;
}


int main()
{
    //Create shared memory for mantaining info about users
    user_info user_status[REGISTERED_USERS];
    initialize_user_info(user_status);
    memcpy(shmem, user_status, sizeof(user_info)*REGISTERED_USERS);

    int ret;
    int listen_socket_id, comm_socket_id;   //socket indexes
    struct sockaddr_in srv_addr, cl_addr;   //address informations struct
    char send_buffer[1024];                 //buffer for sending replies
    pid_t pid;                              

    //Preparation of ip address struct
    memset(&srv_addr, 0, sizeof(srv_addr));
    listen_socket_id = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket_id == -1)
        errorHandler(SOCK_ERR);

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    inet_pton(AF_INET, srv_ipv4, &srv_addr.sin_addr);
    log("address struct preparation...");

    if (-1 == bind(listen_socket_id, (struct sockaddr *)&srv_addr, sizeof(srv_addr)))
        errorHandler(BIND_ERR);

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

            //Child process
            while (true)
            {
                char msgOpcode;
                
                //Get Opcode
                ret = recv(comm_socket_id, (void *)&msgOpcode, sizeof(char), 0);
                if (ret < 0)
                    errorHandler(REC_ERR);
                if (ret = 0)
                    vlog("No message from the server");

                string tmp(1, msgOpcode);
                log("Msg received is " + tmp);
                
                switch (msgOpcode){

                    case CHAT_CMD:
                        ret = handle_chat_request(comm_socket_id);
                        if(ret<0)
                            errorHandler(GEN_ERR);
                        break;

                    case ONLINE_CMD:
                        ret = get_online_users();
                        if(ret<0)
                            errorHandler(GEN_ERR);
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