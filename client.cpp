#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <climits>
#include "constant.h"
#include "util.h"

using namespace std;

void welcome()
{
    cout << " *********************************************************************** " << endl;
    cout << "                           SECURE COMMUNICATION " << endl;
    cout << " *********************************************************************** " << endl;
    cout << "   !exit       Close the application" << endl;
    cout << "   !help       See all the possible commands (work in progress)" << endl;
}

int main(int argc, char* argv[])
{
    int sock_id;                // socket id
    int len;                    // size message
    int size;                   // server response size
    int ret;                    // var to store function return value
    uint16_t sizeMsgServer;     // size msg server on the net

    struct sockaddr_in srv_addr;
    char* risp;
    uint16_t lmsg;
    
    const char* srv_ip = "127.0.0.1";
    const int srv_port = 4242;

    // Socket creation
    sock_id = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_id<0)
        errorHandler(CONN_ERR);
    
    // Initialization for server address
    if(!memset(&srv_addr, 0, sizeof(srv_addr)))
        errorHandler(GEN_ERR); 
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    ret = inet_pton(AF_INET, srv_ip, &srv_addr.sin_addr);
    if(ret<=0)
        errorHandler(CONN_ERR);
    
    // Socket connection
    ret = connect(sock_id, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if(ret < 0)
        errorHandler(CONN_ERR);
    
    welcome();

    while(true)
    {
        // Read msg from the std input
        const char* toSend = NULL;
        string msgFromStdIn;
        printf(" > ");
        cin >> msgFromStdIn;
        toSend = msgFromStdIn.c_str();

        if(msgFromStdIn.compare("!exit")==0)
                break;

        // compute msg len
        len = strlen(toSend)+1; // +1 due to the string terminator that it is not taken into account in strlen
        lmsg = htons(len);
        if(strlen(toSend))
            vlog("Try to send a message with a size of 0");

        // Send string size to the server
        ret = send(sock_id,(void*)&lmsg,sizeof(uint16_t),0);
        if(ret < 0 || ret!=sizeof(uint16_t))
            errorHandler(SEND_ERR);

        // Send the string to the server
        ret = send(sock_id, (void*) toSend, len, 0);
        if(ret < 0 || ret != len)
            errorHandler(SEND_ERR); 

        // Wait for response
        // response size
        ret = recv(sock_id, (void*)&sizeMsgServer, sizeof(uint16_t), 0);  
        if(ret < 0)
            errorHandler(REC_ERR);
        if(ret = 0)
            vlog("No message from the server");

        size = ntohs(sizeMsgServer);
            
        // Buffer for response
        if(size>INT_MAX/sizeof(char))
            errorHandler(INT_OW_ERR);

        risp = (char*)malloc(sizeof(char)*size);
        if(!risp)
            errorHandler(MALLOC_ERR);
            
        // Server response
        ret = recv(sock_id, (void*)risp, size, 0); 
        if(ret < 0)
            errorHandler(REC_ERR);
        if(ret = 0)
            vlog("No message from the server");
            
        printf("%s\n", risp);   

        free(risp);
    }
    
    close(sock_id);
    cout << "Bye Bye" << endl;
    return 0;
}