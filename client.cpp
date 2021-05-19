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

/* This global variable is setted to true if the user is in chat with 
 * another client, to false otherwise*/
bool isChatting = false;


struct commandMSG
{
    uint8_t opcode;
    int userId;
};
size_t CMD_STRUCT_SIZE = sizeof(uint8_t)+sizeof(int);

struct genericMSG
{
    uint8_t opcode;
    uint16_t length;
    unsigned char* payload;
};
size_t GEN_STRUCT_SIZE =  sizeof(uint8_t) + sizeof(uint16_t) + sizeof(unsigned char*);

struct user
{
    int userId;
    unsigned char* username;
    user* next;
};
size_t USER_STRUCT_SIZE =  sizeof(int) + sizeof(unsigned char*) + sizeof(user*);

void welcome()
{
    cout << " *********************************************************************** " << endl;
    cout << "                           SECURE COMMUNICATION " << endl;
    cout << " *********************************************************************** " << endl;
    cout << "   !exit       Close the application" << endl;
    cout << "   !help       See all the possible commands" << endl;
    cout << "-------------------------------------------------------------------------" << endl;
}

void help()
{
    cout << " !users_online" << endl;
    cout << "   Ask the server to return the list of the online users" << endl;
    cout << " !chat" << endl;
    cout << "   Ask the server to start a chat" << endl;
    cout << " !exit" << endl;
    cout << "   Close the application" << endl;
}

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
    else
        return NOT_VALID_CMD;
}

int chat(struct commandMSG* toSend)
{
    toSend->opcode = CHAT_CMD; 
    string username;
    cout << " Work in progress - chat()" << endl;
    cout << " Write the username of the user that you want to contact" << endl;
    printf(" > ");
    cin >> username;
    // Salvo la stringa e la mando al server
    return 0;
}


void free_list_users(struct user* userlist)
{
    struct user* toDelete = userlist;
    struct user* nextDeletion = NULL;

    while(toDelete!=NULL)
    {
        nextDeletion = toDelete->next;
        free(toDelete);
        toDelete = nextDeletion;
    }
}

/*
struct user* retrieveOnlineUsers(int sock_id)
{
    int howMany;
    int ret = recv(sock_id, (void*)&howMany, sizeof(int), 0);  
    if(ret <= 0)
        return NULL;
printf("1\n");
    if(howMany>REGISTERED_USERS)
        return NULL;
printf("2\n");    
    struct user* user_list = NULL;
    struct user* current = NULL;
    struct user* tmp = NULL;

    for(int i = 0; i<howMany; i++)
    {
        int username_size;
        tmp = (struct user*)malloc(USER_STRUCT_SIZE);
        if(!tmp)
            return NULL;
        tmp->next = NULL;
printf("3\n");
        ret = recv(sock_id, (void*)&(tmp->userId), sizeof(int), 0);  
        if(ret <= 0)
        {
            free(tmp);
            free_list_users(user_list);
            return NULL;
        }
printf("4\n");
        ret = recv(sock_id, (void*)&username_size, sizeof(int), 0);  
        if(ret <= 0)
        {
            free(tmp);
            free_list_users(user_list);
            return NULL;
        }
printf("5\n");
        if(username_size>MAX_USERNAME_SIZE)
        {
            free(tmp);
            free_list_users(user_list);
            return NULL;
        }
printf("6\n");
        tmp->username = (unsigned char*)malloc(username_size+1);

        ret = recv(sock_id, (void*)&(tmp->username), username_size, 0);  
        if(ret <= 0)
        {   
            free(tmp);
            free_list_users(user_list);
            return NULL;
        }
printf("7\n");
        tmp->username[username_size] = '\0';

        if(i==0)
            user_list = tmp;
        else
            current->next = tmp;
    
        current = tmp;    
    }
    return user_list;
}

void print_list_users(struct user* userlist)
{
    struct user* tmp = userlist;
    while(tmp!=NULL)
    {
        cout << tmp->userId << "\t" << tmp->username << endl;
        tmp = tmp->next;
    }
}
*/


int main(int argc, char* argv[])
{
    int sock_id;                // socket id
    int len;                    // size message
    int size;                   // server response size
    int ret;                    // var to store function return value
    uint16_t sizeMsgServer;     // size msg server on the net

    struct sockaddr_in srv_addr;
    char* risp;
    
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
        string userInput;
        cout << endl;
        printf(" > ");
        cin >> userInput;
        cout << endl;

        uint8_t commandCode = NOT_VALID_CMD;
        struct genericMSG msgGenToSend;
        struct commandMSG toSend;

        if(!isChatting)
        {
            toSend.opcode = NOT_VALID_CMD;

            commandCode = commandStringHandler(userInput);

            switch (commandCode)
            {
            case CHAT_CMD:
                ret = chat(&toSend);
                if(ret<0)
                    errorHandler(GEN_ERR);
                break;

            case ONLINE_CMD:
                toSend.opcode = ONLINE_CMD;
                break;
            
            case HELP_CMD:
                help();
                break;

            case EXIT_CMD:
                // The command is handled at the end of the while body
                toSend.opcode = EXIT_CMD;
                break;
            
            case NOT_VALID_CMD:
                cout << "Command Not Valid" << endl;
                break;
            
            default:
                cout << "Command Not Valid" << endl;
                break;
            }
        }
        else
        {
            commandCode = MSG;
            msgGenToSend.opcode = commandCode;
            msgGenToSend.payload = NULL;
            msgGenToSend.length = 0;
        }

        if(commandCode!=HELP_CMD) // I have to send nothing to the server if the command is help
        {
            if(isChatting)
            {
                // Set the length of the message
                //len = sizeof(msgGenToSend);
                uint16_t lmsg = htons(GEN_STRUCT_SIZE);
                msgGenToSend.length = lmsg;

                // Send the message to the server
                ret = send(sock_id,(void*)&msgGenToSend,sizeof(msgGenToSend),0);
                if(ret < 0 || ret!=sizeof(msgGenToSend))
                    errorHandler(SEND_ERR);
            }
            else
            {
                // Send the command message to the server
                cout << "Sent " << CMD_STRUCT_SIZE << endl;
                ret = send(sock_id,(void*)&toSend,CMD_STRUCT_SIZE,0);
                
                if(ret < 0 || ret!=CMD_STRUCT_SIZE)
                    errorHandler(SEND_ERR);
            }

            printf(" DBb - wait for server response\n");
            // Wait for response

            // I read the first byte to understand which type of message the server is sending to me
            uint8_t op;
            ret = recv(sock_id, (void*)&op, sizeof(uint8_t), 0);  
            if(ret < 0)
                errorHandler(REC_ERR);
            if(ret = 0)
                vlog("No message from the server");

            if(op==ONLINE_CMD)
            {
                cout << "Online users command handling" << endl;
                /*user* user_list = retrieveOnlineUsers(sock_id);
                if(!user_list)
                {
                    printf(" emaiefnsif\n");
                    errorHandler(GEN_ERR);
                }
                print_list_users(user_list);
                free_list_users(user_list);*/
            }
            else
            {
                cout << " Work in progress " << endl;
            }
    
            if(commandCode==EXIT_CMD)
                break;
        }
    }
    
    close(sock_id);
    cout << "\n Bye Bye" << endl;
    return 0;
}