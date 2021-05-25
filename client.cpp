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

/* This global variable is setted to true when an error occurs*/
bool error = false;

/* Username of the "logged" user*/
string loggedUser;

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
    size_t usernameSize;
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
    if(userlist==NULL)
        return;

    struct user* toDelete = userlist;
    struct user* nextDeletion = NULL;

    while(toDelete!=NULL)
    {
        nextDeletion = toDelete->next;
        free(toDelete->username);
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
    if(user_list!=NULL)
        free_list_users(user_list);

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
        tmp->usernameSize = 0;

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
        if(ret <= 0)
        {
            free(tmp);
            free_list_users(user_list);
            return -1;
        }
        username_size = ntohl(username_size);
        cout << " DBG - Username size: " << username_size << endl;
        tmp->usernameSize = username_size;

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
            free(tmp->username);
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
 * @brief Get the Username From the user id
 * 
 * @param userId 
 * @param userlist 
 * @return string that is the username, NULL if error
 */
string getUsernameFromID(int userId, user* userlist)
{ 
    if(userlist==NULL)
    {
        cout << " Warning: userlist is null " << endl;
        return NULL;
    }

    struct user* tmp = userlist;
    while(tmp!=NULL)
    {
        if(tmp->userId==userId)
        {
            //strncpy((char*)username, (char*)tmp->username, tmp->usernameSize);  
            string username ((char*)(tmp->username)); 
            return username;
        }
        tmp = tmp->next;
    }
    return NULL;
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

    ret = send(sock_id,(void*)msgToSend->payload, msgToSend->length, 0);
    if(ret < 0 || ret!=msgToSend->length)
        return -1;

    free(msgToSend->payload);

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

    uint16_t host_msg_size = ntohs(msg_size);

    // CONTROLLA MSG SIZE PER OVERFLOW
    char* msg_vector = (char*)malloc(host_msg_size);
    if(!msg_vector)
        return -1;

    ret = recv(sock_id, (void*)msg_vector, host_msg_size, 0); 
    if(ret <= 0)
        return -1;

    msg = (string)msg_vector;
    return 0;
}

int authentication(int sock_id)
{
    // This function will contain the authentication procedure
    // performed between client and server. For now we have a simplified version
    bool tooBig = false;
    do{
        if(tooBig)
            cout << " The username inserted is too big! " << endl;
        cout << " Who are you? " << endl;
        cout << " > ";
        cin >> loggedUser;
        if(loggedUser.size()+1>MAX_USERNAME_SIZE)
            tooBig = true;
    }while(tooBig);

    // For now the authentication phase consists in sending the username to the server
    // first - send the size
    uint16_t stringsize = loggedUser.size()+1;
    uint16_t net_stringsize = htons(stringsize);
    int ret = send(sock_id, (void*)&net_stringsize, sizeof(uint16_t), 0);
    if(ret<=0 || ret != sizeof(uint16_t))
        return -1;

    // second - send the username
    ret = send(sock_id, (void*)loggedUser.c_str(), stringsize, 0);
    if(ret<=0 || ret != stringsize)
        return -1;
    
    // For now let's assume that the authentication has been succesfully executed
    return 0;
}

int main(int argc, char* argv[])
{     
    int sock_id;                // socket id
    int len;                    // size message
    int size;                   // server response size
    int ret;                    // var to store function return value
    uint16_t sizeMsgServer;     // size msg server on the net

    uint8_t commandCode = NOT_VALID_CMD;

    // Data structure which represents a generic message
    struct genericMSG msgGenToSend;
    msgGenToSend.opcode = MSG;
    msgGenToSend.payload = NULL;
    msgGenToSend.length = 0;

    // Data structure which represents a command message
    struct commandMSG cmdToSend;
    cmdToSend.opcode = NOT_VALID_CMD;
    cmdToSend.userId = -1;

    // pointer to the list of online users
    user* user_list = NULL;

    // username of the user involved in chat with me
    string counterpart;

    struct sockaddr_in srv_addr;
    char* risp;
    
    const char* srv_ip = "127.0.0.1";
    const int srv_port = 4242;
   
    // Socket creation
    sock_id = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_id<0){
        error = true;
        errorHandler(CONN_ERR);
        goto close_all;
    }
    
    // Initialization for server address
    if(!memset(&srv_addr, 0, sizeof(srv_addr))){
        error = true;
        errorHandler(GEN_ERR); 
        goto close_all;
    }

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(srv_port);
    ret = inet_pton(AF_INET, srv_ip, &srv_addr.sin_addr);
    if(ret<=0){
        error = true;
        errorHandler(CONN_ERR);
        goto close_all;
    }
    // Socket connection
    ret = connect(sock_id, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if(ret < 0){
        error = true;
        errorHandler(CONN_ERR);
        goto close_all;
    }
    
    welcome();

   
    ret = authentication(sock_id);
    if(ret<0)
    {
        error = true;
        errorHandler(AUTHENTICATION_ERR);
        goto close_all;
    }

    cout << " --- AUTHENTICATION DONE --- " << endl;

    while(true)
    {
        // Read msg from the std input
        string userInput;
        cout << endl;
        printf(" > ");
        cin >> userInput;
        cout << endl;

        if(!isChatting || (isChatting==true && userInput.compare("!stop_chat")))
        {
            /* ****************************************
             *          COMMAND SECTION
             * *****************************************/
            commandCode = commandStringHandler(userInput);

            switch (commandCode)
            {
                case CHAT_CMD:
                    ret = chat(&cmdToSend);
                    if(ret<0){
                        error = true;
                        errorHandler(GEN_ERR);
                        goto close_all;
                    }
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
             /* ****************************************
             *          CHAT SECTION
             * *****************************************/
            commandCode = MSG;
            msgGenToSend.opcode = MSG;
            msgGenToSend.length = userInput.size();
            msgGenToSend.payload = (unsigned char*)malloc(msgGenToSend.length);
            if(!msgGenToSend.payload){
                error = true;
                errorHandler(MALLOC_ERR);
                goto close_all;
            }

            strncpy((char*)msgGenToSend.payload, userInput.c_str(), userInput.size());  
        }

        /* ********************************
         *  COMMUNICATIONS WITH SERVER 
         * ********************************/
        if(commandCode!=HELP_CMD) // I have to send nothing to the server if the command is help
        {
             /* ****************************************
             *          SEND TO THE SERVER SECTION
             * *****************************************/
            if(isChatting && cmdToSend.opcode!=STOP_CHAT)
            {
                cout << " DBG - Sending message <" << msgGenToSend.payload << "> of length <" << msgGenToSend.length << endl;
                ret = send_message(sock_id, &msgGenToSend);
                if(ret!=0){
                    error = true;
                    errorHandler(SEND_ERR);
                    goto close_all;
                }
                cout << " DBG -  Message sent " << endl;
            }
            else
            {
                // Send the command message to the server
                cout << " DBG - I have to sent a command message to the server ... " << endl;
                ret = send_command_to_server(sock_id, &cmdToSend);
                if(ret!=0){
                    error = true;
                    errorHandler(SEND_ERR);
                    goto close_all;
                }
                cout << " DBG - Command to server sent" << endl;
            }
            

            /* ****************************************
             *      RECEIVE FROM THE SERVER SECTION
             * *****************************************/
            cout << " DBG - wait for server response" << endl;

            // I read the first byte to understand which type of message the server is sending to me
            uint8_t op;
            ret = recv(sock_id, (void*)&op, sizeof(uint8_t), 0);  
            if(ret <= 0){
                error = true;
                errorHandler(REC_ERR);
                goto close_all;
            }

            /* ****************************************************************
             * Action to perform considering the things sent from the server
             * ****************************************************************/
            switch (op)
            {
                case ONLINE_CMD:
                {
                    cout << " DBG - Online users command handling" << endl;
                    ret = retrieveOnlineUsers(sock_id, user_list);
                    if(ret == 0){
                        cout << " ** No users are online ** " << endl;
                    }
                    else if (ret==-1){
                        error = true;
                        errorHandler(GEN_ERR);
                        goto close_all;
                    }
                    else{ // correct output
                        if(print_list_users(user_list)!=0){
                            error = true;
                            errorHandler(GEN_ERR);
                            goto close_all;
                        }
                    }
                    // free before the termination of the program or before a new retrieveOnlineUsers        
                    // free_list_users(user_list);
                }
                break;

                case CHAT_POS:
                {
                    // The server says that the client that I want to contact is available
                    int counterpart_id;
                   
                    ret = recv(sock_id, (void*)&counterpart_id, sizeof(int), 0);  
                    if(ret < 0) {
                        error = true;
                        errorHandler(REC_ERR);
                        goto close_all;
                    }

                    counterpart = getUsernameFromID(counterpart_id, user_list);
                    if(counterpart.empty()){
                        error = true;
                        errorHandler(GEN_ERR);
                        goto close_all;
                    }
                    
                    if(cmdToSend.userId!=counterpart_id)
                    {
                        cout << " Server internal error: the user id requested and the one available does not match" << endl;
                        break;
                    }

                    isChatting = true;

                    cout << " ******************************** " << endl;
                    cout << "               CHAT               " << endl;
                    cout << " Send a message to " <<  counterpart << endl;
                }  
                break;

                case CHAT_RESPONSE:
                {
                    string message;
                    ret = receive_message(sock_id, message);
                    if(ret!=0) {
                        error = true;
                        errorHandler(REC_ERR);
                        goto close_all;
                    }

                    if(counterpart.empty()){
                        error = true;
                        errorHandler(GEN_ERR);
                        goto close_all;
                    }
                    cout << " " << counterpart << " -> " << message << endl;
                }
                break;

                default:
                {
                    error = true;
                    errorHandler(SRV_INTERNAL_ERR);
                    goto close_all;
                }
                break;
            }
        }
    
        if(commandCode==EXIT_CMD)
            break;
        
    }

close_all:
    if(msgGenToSend.payload)
        free(msgGenToSend.payload);

    free_list_users(user_list);
    close(sock_id);
    
    if(error) {
        cout << " Forced secure termination " << endl;
        exit(-1);
    }
    else {
        cout << "\n Bye Bye" << endl;
        return 0;
    }  
}