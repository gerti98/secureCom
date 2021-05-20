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
#define SEM_OPEN_ERR     0x0B
#define SEM_WAIT_ERR     0x0C
#define SEM_POST_ERR     0x0D
#define SEM_CLOSE_ERR     0x0E
#define MMAP_ERR    0x0F

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

#define VERBOSITY_LEVEL 3


/**************************
*   OTHER CONSTANTS
***************************/

#define SOCKET_QUEUE 10
#define REGISTERED_USERS 5
#define MAX_USERNAME_SIZE 16
#define BUFFER_MAX  102400

/**************************
*   CRYPTO CONSTANTS
***************************/
#define DIEGST_DEFAULT EVP_sha256();
#define SYMMETRIC_DEFAULT EVP_aes_256_cbc();
#define AUTH_ENCRYPT_DEFAULT EVP_aes_256_gcm();
#define NUANCE_DEFAULT 32;
#endif