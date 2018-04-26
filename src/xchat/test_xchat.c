/* test_xchat.c: useful for testing various features of chats.
   compile with: gcc -o test -I../ test_xchat.c xcommon.c retransmit.c message.c cutil.c store.c ../lib/.libs/liballnet-3.2.1.a -lcrypto -lpthread
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "lib/packet.h"
#include "lib/pipemsg.h"
#include "lib/util.h"
#include "lib/priority.h"
#include "lib/allnet_log.h"
#include "lib/keys.h"
#include "chat.h"
#include "store.h"
#include "cutil.h"
#include "retransmit.h"
#include "xcommon.h"

static void print_contact (const char * contact, int index, int hidden)
{
  printf ("  %scontact [%d] is '%s', chat size %" PRId64 ", %s hidden\n",
          ((hidden) ? "hidden " : ""), index, contact,
          conversation_size (contact), ((is_hidden (contact)) ? "is" : "not"));
}

static void print_contacts (const char * desc)
{
  printf ("%s:\n", desc);
  char ** contacts = NULL;
  int n = all_contacts (&contacts);
  int i;
  for (i = 0; i < n; i++)
    print_contact (contacts [i], i, 0);
  free (contacts);
  contacts = NULL;
  n = hidden_contacts (&contacts);
  if ((n > 0) && (contacts != NULL)) {
    printf ("%d hidden contacts:\n", n);
    for (i = 0; i < n; i++)
      print_contact (contacts [i], i, 1);
    free (contacts);
  }
}

int main (int argc, char ** argv)
{
  log_to_output (get_option ('v', &argc, argv));
  struct allnet_log * log = init_log ("xchatr");
  pd p = init_pipe_descriptor (log);
  int sock = xchat_init (argv [0], p);
  if (sock < 0)
    return 1;
  int result;

#if 0
  char * from = "test-group";
  char * to = "group-test";
  print_contacts ("initial contacts");
  printf ("renaming %s to %s\n", from, to);
  result = rename_contact (from, to);
  printf ("renaming returned %d\n", result);
  print_contacts ("after renaming");

  printf ("reverse renaming %s to %s\n", to, from);
  result = rename_contact (to, from);
  printf ("reverse renaming returned %d\n", result);
  print_contacts ("after reverse renaming");

  printf ("hiding %s\n", from);
  result = hide_contact (from);
  printf ("hide_contact (%s) gave %d\n", from, result);
  print_contacts ("after hiding");

  printf ("unhiding %s\n", from);
  result = unhide_contact (from);
  printf ("unhide_contact (%s) gave %d\n", from, result);
  print_contacts ("after unhiding");
#endif /* 0 */

  const char * tc = "test_contact_for_deletion";
  unsigned char local [ADDRESS_SIZE];
  result = create_contact (tc, 4096, 1, NULL, 0, local, 16, NULL, 0);
  printf ("create_contact (%s) gave %d\n", tc, result);
  print_contacts ("after creating");
sleep (60);
  print_contacts ("after sleeping");

  result = delete_conversation (tc);
  printf ("delete_conversation (%s) gave %d\n", tc, result);
  print_contacts ("after deleting conversation");
  result = hide_contact (tc);
  print_contacts ("after hiding contact");
  result = delete_contact (tc);
  printf ("delete_contact (%s) gave %d\n", tc, result);
  print_contacts ("after deleting contact");

  printf ("main complete\n");
}
