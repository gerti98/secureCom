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
    switch (errorId)
    {
        case GEN_ERR:
            printf("Generic Error\n");
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

        case INT_OW_ERR:
            printf("Integer overflow avoided");
            break;

        case SEM_OPEN_ERR:
            printf("Error on sem_open");
            break;

        case SEM_POST_ERR:
            printf("Error on sem_post");
            break;

        case SEM_WAIT_ERR:
            printf("Error on sem_wait");
            break;

        case SEM_CLOSE_ERR:
            printf("Error on sem_close");
            break;
        
        case SRV_INTERNAL_ERR:
            printf("Server internal error");
            
        default:
            printf("Generic Error\n");
            break;
    }

    exit(-1);
}