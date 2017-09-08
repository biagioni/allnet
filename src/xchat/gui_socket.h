/* gui_socket.h: define functions shared among the gui files */

#ifndef ALLNET_CHAT_GUI_SOCKET_H
#define ALLNET_CHAT_GUI_SOCKET_H

/* packet types received from the GUI */
#define GUI_CONTACTS 				1
#define GUI_SUBSCRIPTIONS 			2
#define GUI_CONTACT_EXISTS 			3
#define GUI_CONTACT_IS_GROUP 			4
#define GUI_HAS_PEER_KEY 			5

#define GUI_CREATE_GROUP 			10
#define GUI_MEMBERS 				11
#define GUI_MEMBERS_RECURSIVE			12
#define GUI_MEMBER_OF_GROUPS 			13
#define GUI_MEMBER_OF_GROUPS_RECURSIVE		14

#define GUI_RENAME_CONTACT			20
#define GUI_DELETE_CONTACT			21
#define GUI_CLEAR_CONVERSATION			22

#define GUI_QUERY_VARIABLE			30
#define GUI_SET_VARIABLE			31
#define GUI_UNSET_VARIABLE			32

#define GUI_VARIABLE_VISIBLE			1
#define GUI_VARIABLE_NOTIFY			2
#define GUI_VARIABLE_SAVING_MESSAGES		3
#define GUI_VARIABLE_COMPLETE			4  /* only set/query Complete */
#define GUI_VARIABLE_READ_TIME			5  /* only set ReadTime */
#define GUI_VARIABLE_HOP_COUNT			6  /* only query hop count */
#define GUI_VARIABLE_SECRET			7  /* only query hop count */

#define GUI_GET_MESSAGES			40
#define GUI_SEND_MESSAGE			41
#define GUI_SEND_BROADCAST			42

#define GUI_KEY_EXCHANGE			50
#define GUI_SUBSCRIBE				51
#define GUI_TRACE				52

#define GUI_BUSY_WAIT				60

/* codes sent to the GUI when receiving allnet messages, with no response */

#define GUI_CALLBACK_MESSAGE_RECEIVED		70
#define GUI_CALLBACK_MESSAGE_ACKED		71
#define GUI_CALLBACK_CONTACT_CREATED		72
#define GUI_CALLBACK_SUBSCRIPTION_COMPLETE	73
#define GUI_CALLBACK_TRACE_RESPONSE		74

#include <unistd.h>       /* pid_t */
#include <inttypes.h>     /* int64_t */

#include "lib/pipemsg.h"  /* pd */

/* start java and return the PID of the java process */
extern pid_t start_java (const char * arg);  /* gui_start_java.c */

/* loop to listen on the gui socket and respond appropriately */
extern void * gui_respond_thread (void * arg);  /* gui_response.c */

/* loop to listen on the allnet socket and respond appropriately */
extern void gui_socket_main_loop (int gui_sock, /* gui_callback.c */
                                  int allnet_sock, pd p);


/* returns 1 for success or 0 for failure */
/* uses a mutex to avoid interleaving packets on the connection,
 * so should be called by all gui code for sending on the gui socket */
extern int gui_send_buffer (int sock, char *buffer, int64_t length);

/* exit code should be 0 for normal exit, 1 for error exit */
extern void stop_chat_and_exit (int exit_code);

#endif /* ALLNET_CHAT_GUI_SOCKET_H */
