#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "util.h"
#include "constant.h"

using namespace std;

void log(string msg){
    if(VERBOSITY_LEVEL >= 1)
        cout << "[LOG] " << msg << endl;
}


void vlog(string msg){
    if(VERBOSITY_LEVEL >= 2)
        cout << "[VLOG] " << msg << endl;
}

void vvlog(string msg){
    if(VERBOSITY_LEVEL >= 3)
        cout << "[VVLOG] " << msg << endl;
}

void errorHandler(uint16_t errorId = GEN_ERR)
{
    printf(" ERR - ");
    switch (errorId)
    {
        case GEN_ERR:
            printf("Generic Error\n");
            break;

        case BIND_ERR:
            printf("Bind Error\n");
            break;

        case LISTEN_ERR:
            printf("Listen Error\n");
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
            printf("Malloc failed\n");
            break;

        case INT_OW_ERR:
            printf("Integer overflow avoided\n");
            break;

        case SEM_OPEN_ERR:
            printf("Error on sem_open\n");
            break;

        case SEM_POST_ERR:
            printf("Error on sem_post\n");
            break;

        case SEM_WAIT_ERR:
            printf("Error on sem_wait\n");
            break;

        case SEM_CLOSE_ERR:
            printf("Error on sem_close\n");
            break;
        
        case SRV_INTERNAL_ERR:
            printf("Server internal error\n");
            break;
        
        case AUTHENTICATION_ERR:
            printf("Error during authentication Phase\n");
            break;
            
        default:
            printf("Generic Error\n");
            break;
    }

   // exit(-1);
}