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
    
    case INT_OW_ERR
        printf("Integer overflow avoided")
        break;

    default:
        perror("Generic Error\n");
        break;
    }

    exit(-1);
}