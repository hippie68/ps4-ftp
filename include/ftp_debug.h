/* Include this header file to send debug messages from the PS4 to a computer.
 * Adjust DEBUG_IP and DEBUG_PORT to match your computer's network setup.
 * Print debug messages with the function debug_msg().
 *
 * In this order:
 * 1. Listen to messages on your computer via netcat:
 *    "netcat -l 9023"
 * 2. Start the FTP server.
 */

#ifndef FTP_DEBUG_H
#define FTP_DEBUG_H
#endif

// Uncomment this line to enable debug messages
//#define DEBUG_SOCKET

#ifdef DEBUG_SOCKET
#define DEBUG_IP "192.168.x.x"
#define DEBUG_PORT 9023
#define debug_msg(...) printf_debug(__VA_ARGS__)
#else
#define debug_msg(...)
#endif
