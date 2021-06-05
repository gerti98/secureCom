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

using namespace std;
using uchar=unsigned char;
typedef void (*sighandler_t)(int);
#define PUBKEY_DEFAULT_SER 451


struct msg_to_relay{
    long type;
    char buffer[800];
};


void log(string s){
    cout << s << endl;
}


int main(){

    msg_to_relay msg;
    msg.type = 1;

    
    //Write to the message queue
    key_t key = ftok("prova", 65); 
    int msgid = msgget(key, 0666 | IPC_CREAT);
    
    

    int ret = msgrcv(msgid, &msg, sizeof(msg), 1, 1);
    log("read msg, ret: " + to_string(ret));
    
    
    return 0;
}