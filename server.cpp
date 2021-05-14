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

#include "constant.h"
#include "util.h"

using namespace std;

//Parameters of connection
const char *srv_ipv4 = "127.0.0.1";
;
const int srv_port = 4242;

//TODO: maybe create a conf file to get configuration parameters eventually


int handleChatRequest(int comm_socket){
    log("Chat request arrived");
    return 0;    
}


int getOnlineUsers(){
    log("Get Online Users request arrived");
    return 0;    
}

int main()
{
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
                        ret = handleChatRequest(comm_socket_id);
                        if(ret<0)
                            errorHandler(GEN_ERR);
                        break;

                    case ONLINE_CMD:
                        ret = getOnlineUsers();
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