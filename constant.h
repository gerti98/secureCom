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
#define BUFFER_MAX  102400

/*
 *  COMMAND CODE
 */
#define NOT_VALID_CMD   0x1
#define EXIT_CMD        0x2
#define ONLINE_CMD      0x3
#define CHAT_CMD        0x4
#define HELP_CMD        0x5
#define MSG             0x6

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
#define REGISTERED_USERS 5

/**************************
*   CRYPTO CONSTANTS
***************************/
#define DIEGST_DEFAULT EVP_sha256();
#define SYMMETRIC_DEFAULT EVP_aes_256_cbc();
#define AUTH_ENCRYPT_DEFAULT EVP_aes_256_gcm();

#endif