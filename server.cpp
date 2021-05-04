#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

//Parameters of connection
const char* srv_ipv4 = "192.168.4.5";
const int srv_port = 4242;

//TODO: maybe create a conf file to get configuration parameters eventually

int main(){
    int ret, listen_socket_id, comm_socket_id;
    struct sockaddr_in srv_addr, cl_addr;
    char send_buffer[1024];
    pid_t pid;

    
    //Preparation of ip address struct
    memset(&srv_addr, 0, sizeof(srv_addr));
    listen_socket_id = socket(AF_INET, SOCK_STREAM, 0);
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port); 
    inet_pton(AF_INET, srv_ipv4, &srv_addr.sin_addr);
    cout << "[LOG] address struct preparation..." << endl;
    
    ret = bind(listen_socket_id, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    ret = listen(listen_socket_id, 10);
    unsigned int len = sizeof(cl_addr);
    cout << "[LOG] socket is listening..." << endl;

    while(true){
        comm_socket_id = accept(listen_socket_id, (struct sockaddr*)&cl_addr, &len);
        pid = fork();

        if(pid == 0){
            //child process
            close(listen_socket_id);
            cout << "[LOG] connection established with client" << endl;

            //Send ACK to client
            strcpy(send_buffer, "ACK");
            len = strlen(send_buffer);
            ret = send(comm_socket_id, (void*)send_buffer, len, 0);
            if(ret < len){
                cerr << "Error on the send" << endl;
                exit(-1);
            }

            cout << "[LOG] ACK sent to client" << endl;

            close(comm_socket_id);
            exit(0);
        } else if(pid == -1){
            cerr << "Error on fork" << endl;
            exit(-1);
        }

        close(comm_socket_id);
    }
}