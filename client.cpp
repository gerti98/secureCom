#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <vector>
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

struct genericMSG
{
    uint8_t opcode;
    uint16_t length;
    unsigned char* payload;
};

struct user
{
    int userId;
    unsigned char* username;
    user* next;
};

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
    cout << " !users_online" << endl;
    cout << "   Ask the server to return the list of the online users" << endl;
    cout << " !chat" << endl;
    cout << "   Ask the server to start a chat" << endl;
    cout << " !exit" << endl;
    cout << "   Close the application" << endl;
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
    else if(cmd.compare("!stop_chat"))
        return STOP_CHAT;
    else
        return NOT_VALID_CMD;
}

/**
 * @brief Handle the client side part of the command chat
 * 
 * @param toSend 
 * @return int -1 if error, 0 otherwise
 */
int chat(struct commandMSG* toSend)
{
    toSend->opcode = CHAT_CMD; 
    cout << " Write the username of the user that you want to contact" << endl;
    printf(" > ");
    cin >> toSend->userId;
    return 0;
}

/**
 * @brief Free the list of users
 * 
 * @param userlist head of the list that must be cleaned
 */
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

/**
 * @brief The function receives from the server the list of the user and it store it
 * 
 * @param sock_id socket id
 * @param userlist data structure to store the list
 * @return The number of online users, -1 if error, 0 if no user in the list
 */
int retrieveOnlineUsers(int sock_id, user*& user_list)
{
    unsigned int howMany;
    int ret = recv(sock_id, (void*)&howMany, sizeof(int), 0);  
    howMany = ntohl(howMany);
    cout << " DBG - Number of users: " << howMany << endl;
    
    if(ret <= 0)
        return -1;

    if(howMany==0)
        return 0;
    
    if(howMany>REGISTERED_USERS)
        return -1;
  
    struct user* current = NULL;
    struct user* tmp = NULL;

    for(int i = 0; i<howMany; i++)
    {
        cout << " DBG - i: " << i << endl;
        int username_size;
        tmp = (struct user*)malloc(sizeof(user));

        if(!tmp)
        {
            cout << "Malloc failed " << endl; 
            return -1;
        }
        tmp->username = NULL;
        tmp->userId = -1;
        tmp->next = NULL;

        ret = recv(sock_id, (void*)&(tmp->userId), sizeof(int), 0);  
        tmp->userId = ntohl(tmp->userId);
        cout << " DBG - User id: " << tmp->userId << endl;
        if(ret <= 0)
        {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }

        ret = recv(sock_id, (void*)&username_size, sizeof(int), 0);  
        username_size = ntohl(username_size);
        cout << " DBG - Username size: " << username_size << endl;
        if(ret <= 0)
        {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }

        if(username_size>MAX_USERNAME_SIZE)
        {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }

        tmp->username = (unsigned char*)malloc(username_size+1);
        ret = recv(sock_id, (void*)(tmp->username), username_size, 0);  
        if(ret <= 0)
        {   
            free(tmp);
            free_list_users(user_list);
            return -1;
        }
        
        tmp->username[username_size] = '\0';

        cout << " DBG - Username: " << tmp->username << endl;
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
    //cout << "print_list_users" << endl; 
    if(userlist==NULL)
    {
        cout << " Warning: userlist is null " << endl;
        return -1;
    }

    struct user* tmp = userlist;
    cout << " **** USER LIST **** " << endl;
    cout << "  ID \t Username" << endl;
    while(tmp!=NULL)
    {
        cout << "  " << tmp->userId << " \t " << tmp->username << endl;
        tmp = tmp->next;
    }
    cout << " ****************** " << endl;

    return 0;
}


/**
 * @brief It is in charge of handlig the sending of a command to the server
 * @param sock_id socket id
 * @param cmdToSend data structure which represent the message to send
 * @return -1 in case of error
 * */
int send_command_to_server(int sock_id, commandMSG* cmdToSend)
{
    int ret = send(sock_id,(void*)&cmdToSend->opcode, sizeof(uint8_t), 0);
    if(ret < 0 || ret!=sizeof(uint8_t))
        return -1;
                
    if(cmdToSend->opcode==CHAT_CMD)
    {
        ret = send(sock_id,(void*)&cmdToSend->userId, sizeof(int), 0);
        if(ret < 0 || ret!=sizeof(int))
            return -1;
    }
    return 0;
}

/**
 * @brief It send the message to the server
 * 
 * @param sock_id socket id
 * @param msgToSend data structure that contains the info for the message
 * @return int 
 */
int send_message(int sock_id, genericMSG* msgToSend)
{
    int ret = send(sock_id,(void*)&msgToSend->opcode, sizeof(uint8_t), 0);
    if(ret < 0 || ret!=sizeof(uint8_t))
        return -1;
                
    uint16_t size = htons(msgToSend->length);
    ret = send(sock_id,(void*)&size, sizeof(uint16_t), 0);
    if(ret < 0 || ret!=sizeof(uint16_t))
        return -1;

    ret = send(sock_id,(void*)&msgToSend->payload, msgToSend->length, 0);
    if(ret < 0 || ret!=msgToSend->length)
        return -1;

    return 0;
}

/**
 * @brief Receive a message sent by the other communication party and forwarded by the server
 * 
 * @param sock_id socket id
 * @param msg string where the received message is inserted
 * @return int -1 id error, 0 otherwise
 */
int receive_message(int sock_id, string msg)
{
    uint16_t msg_size;
    int ret = recv(sock_id, (void*)&msg_size, sizeof(uint16_t), 0); 
    if(ret <= 0)
        return -1;

    uint16_t real_size = ntohs(msg_size);
    ret = recv(sock_id, (void*)&msg, msg_size, 0); 
    if(ret <= 0)
        return -1;

    return 0;
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
        msgGenToSend.opcode = MSG;
        msgGenToSend.payload = NULL;
        msgGenToSend.length = 0;

        struct commandMSG cmdToSend;
        cmdToSend.opcode = NOT_VALID_CMD;
        cmdToSend.userId = -1;

        if(!isChatting || (isChatting==true && userInput.compare("!stop_chat")))
        {
            commandCode = commandStringHandler(userInput);

            switch (commandCode)
            {
                case CHAT_CMD:
                    ret = chat(&cmdToSend);
                    if(ret<0)
                        errorHandler(GEN_ERR);
                break;

                case ONLINE_CMD:
                    cmdToSend.opcode = ONLINE_CMD;
                break;
            
                case HELP_CMD:
                    help();
                break;

                case EXIT_CMD:
                    // The command is handled at the end of the while body
                    cmdToSend.opcode = EXIT_CMD;
                break;
            
                case STOP_CHAT:
                    cmdToSend.opcode = STOP_CHAT;
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
            msgGenToSend.opcode = MSG;
            msgGenToSend.length = userInput.size();
            msgGenToSend.payload = (unsigned char*)malloc(msgGenToSend.length);
            if(!msgGenToSend.payload)
                errorHandler(MALLOC_ERR);

            strncpy((char*)msgGenToSend.payload, userInput.c_str(), userInput.size());  

            cout << "DBG - Invio il messaggio <" << msgGenToSend.payload << "> of length <" << msgGenToSend.length << endl;
        }

        if(commandCode!=HELP_CMD) // I have to send nothing to the server if the command is help
        {
            if(isChatting && cmdToSend.opcode!=STOP_CHAT)
            {
                ret = send_message(sock_id, &msgGenToSend);
                if(ret!=0)
                    errorHandler(SEND_ERR);
                cout << " Message sent " << endl;
            }
            else
            {
                // Send the command message to the server
                cout << " DBG - I have to sent a command message to the server ... " << endl;
                ret = send_command_to_server(sock_id, &cmdToSend);
                if(ret!=0)
                    errorHandler(SEND_ERR);
                cout << " DBG - Command to server sent" << endl;
            }

            cout << " DBG - wait for server response" << endl;

            // I read the first byte to understand which type of message the server is sending to me
            uint8_t op;
            ret = recv(sock_id, (void*)&op, sizeof(uint8_t), 0);  
            if(ret < 0)
                errorHandler(REC_ERR);
            if(ret == 0)
                vlog("No message from the server");


            switch (op)
            {
                case ONLINE_CMD:
                {
                    cout << " DBG - Online users command handling" << endl;

                    user* user_list = NULL;
                    ret = retrieveOnlineUsers(sock_id, user_list);
                    if(ret == 0)
                        cout << " ** No users are online ** " << endl;
                    else if (ret==-1)
                        errorHandler(GEN_ERR);
                    else // correct output
                        if(print_list_users(user_list)!=0)
                            errorHandler(GEN_ERR);
                    // clean        
                    free_list_users(user_list);
                }
                break;

                case CHAT_POS:
                {
                    // The server says that the client that I want to contact is available
                    int peer_id;
                    ret = recv(sock_id, (void*)&peer_id, sizeof(int), 0);  
                    if(ret < 0)
                        errorHandler(REC_ERR);
                    
                    if(cmdToSend.userId!=peer_id)
                    {
                        cout << " Server internal error: the user id requested and the one available does not match" << endl;
                        break;
                    }

                    isChatting = true;

                    cout << " ******************************** " << endl;
                    cout << "               CHAT               " << endl;
                    cout << " Send a message!" << endl;
                }  
                break;

                case CHAT_RESPONSE:
                {
                    string message;
                    ret = receive_message(sock_id, message);
                    if(ret!=0)
                        errorHandler(REC_ERR);
                    cout << " CHAT -> " << message << endl;
                }
                break;

                default:
                    errorHandler(SRV_INTERNAL_ERR);
                break;
            }
        }
    
        if(commandCode==EXIT_CMD)
            break;
        
    }
    
    close(sock_id);
    cout << "\n Bye Bye" << endl;
    return 0;
}