#ifndef FUNCTIONS_CONSTANTS_INCLUDED
#define FUNCTIONS_CONSTANTS_INCLUDED


/*
* ERROR CONSTANTS
*/
#define GEN_ERR     0x00
#define CONN_ERR    0x01
#define SEND_ERR    0x02
#define REC_ERR     0x03
#define MALLOC_ERR  0x04
#define SOCK_ERR    0x05
#define BIND_ERR    0x06
#define LISTEN_ERR    0x07
#define CLOSE_ERR   0x08
#define FORK_ERR    0x09
#define INT_OW_ERR  0x0A


/*
 *  LOGGING CONSTANTS
 *  ---------------------------------
 *  FUN     |   MINUMUM VERBOSITY
 *  ---------------------------------
 *  log     |   1
 *  vlog    |   2
 *  vvlog   |   3
*/

#define VERBOSITY_LEVEL 1


/**************************
*   OTHER CONSTANTS
***************************/

#define SOCKET_QUEUE 10



#endif