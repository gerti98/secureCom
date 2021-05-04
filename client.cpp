#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include "errorConstant.h"

using namespace std;

void errorHandler(uint16_t errorId = GEN_ERR)
{
    switch (errorId)
    {
    case GEN_ERR:
        perror("Generic Error\n");
        break;
    
    case CONN_ERR:
        perror("Connection Error\n");
        break;
    
    case SEND_ERR:
        perror("Error during sending\n");
        break;
    
    case REC_ERR:
        perror("Error during receiving\n");
        break;

    case MALLOC_ERR:
        printf("Malloc failed");
        break;

    default:
        perror("Generic Error\n");
        break;
    }

    exit(-1);
}


int main(int argc, char* argv[])
{
    int sock_id;                // socket id
    int len;                    // size message
    int size;                   // server response size
    uint16_t sizeMsgServer;     // size msg server on the net
    

    struct sockaddr_in srv_addr;
    char* risp;
    uint16_t lmsg;
    
    const char* srv_ip = "127.0.0.1";
    const int srv_port = 4242;

    // Socket creation
    sock_id = socket(AF_INET, SOCK_STREAM, 0);
    
    // Initialization for server address
    memset(&srv_addr, 0, sizeof(srv_addr)); 
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    inet_pton(AF_INET, srv_ip, &srv_addr.sin_addr);
    
    // Socket connection
    int ret = connect(sock_id, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    
    if(ret < 0)
        errorHandler(CONN_ERR);

    char* toSend = "Test Message";

    len = strlen(toSend)+1; // +1 due to the string terminator that it is not taken into account in strlen
    lmsg = htons(len);
    
    // Send string sizeto the server
    ret = send(sock_id,(void*)&lmsg,sizeof(uint16_t),0);
        
    // Send the string to the server
    ret = send(sock_id, (void*) toSend, len, 0);
     
    if(ret < 0)
        errorHandler(SEND_ERR); 

    // Wait for response
    // response size
    ret = recv(sock_id, (void*)&sizeMsgServer, sizeof(uint16_t), 0);
        
    if(ret < 0)
        errorHandler(REC_ERR);
    
    size = ntohs(sizeMsgServer);
        
    // Buffer for response
    risp = (char*)malloc(sizeof(char)*size);
       
    if(!risp)
        errorHandler(MALLOC_ERR);
        
    // Server response
    ret = recv(sock_id, (void*)risp, size, 0);
        
    if(ret < 0)
        errorHandler(REC_ERR);
          
    printf("%s\n", risp);   

    //memset(&buffer, 0, 1024);
    free(risp);
    //memset(&tosend, 0, 1024);

    close(sock_id);

    return 0;
}