//
//  XChatSocket.m
//  xchat UI
//
//  Created by e on 2015/05/22.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
@import CoreFoundation;
#import "AppDelegate.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <dirent.h>

#import "XChat.h"
#import "ConversationUITextView.h"
#import "ContactsUITableViewController.h"
#import "KeyExchangeUIViewController.h"
#import "NewContactViewController.h"
#import "MoreUIViewController.h"

#include "xcommon.h"
#include "limits.h"
#include "lib/util.h"
#include "lib/pipemsg.h"
#include "xchat/cutil.h"
#include "lib/app_util.h"
#include "lib/allnet_log.h"
#include "lib/trace_util.h"
#include "lib/configfiles.h"

@interface XChat ()

@property int sock;
@property ConversationUITextView * conversation;
@property ContactsUITableViewController * contacts;
@property KeyExchangeUIViewController * keyExchange;
@property NewContactViewController * ncvcForNewContact;
@property MoreUIViewController * more;
@property CFRunLoopSourceRef runLoop;

@end

@implementation XChat

// globals
static pthread_mutex_t key_generated_mutex;
static int waiting_for_key = 0;
static char * keyContact = NULL;
static pd p;

// hack to make self object available to C code -- should only be one Xchat object anyway
static XChat * mySelf = NULL;
static void * splitPacketBuffer = NULL;

- (void) initialize: (ConversationUITextView *) conversation contacts: (ContactsUITableViewController *) contacts vc: (NewContactViewController *) vcForNewContact mvc: (MoreUIViewController *) mvc {
  NSLog(@"calling xchat_init\n");
  self.conversation = conversation;
  self.contacts = contacts;
  self.more = mvc;
  struct allnet_log * alog = init_log ("ios xchat");
  p = init_pipe_descriptor(alog);
  splitPacketBuffer = NULL;
  self.sock = xchat_init ("xchat", NULL, p);
  NSLog(@"self.sock is %d\n", self.sock);
  self.ncvcForNewContact = vcForNewContact;
  // NSLog(@"done calling xchat_init, socket %d, conversation %p\n", self.sock, self.conversation);
  CFSocketRef iOSSock = CFSocketCreateWithNative(NULL, self.sock, kCFSocketDataCallBack,
                                                 (CFSocketCallBack)&dataAvailable, NULL);
  // if you ever need to bind, use CFSocketSetAddress -- but not needed here
  self.runLoop = CFSocketCreateRunLoopSource(NULL, iOSSock, 100);
  CFRunLoopRef currentRunLoop = CFRunLoopGetCurrent();
  CFRunLoopAddSource(currentRunLoop, self.runLoop, kCFRunLoopCommonModes);
  mySelf = self;
  // NSLog(@"Xchat.m: initialized my socket %d\n", self.sock);
  pthread_mutex_init(&key_generated_mutex, NULL);
  waiting_for_key = 0;
}

- (void)disconnect {
  NSLog (@"Xchat disconnect socket %d\n", self.sock);
  xchat_end (self.sock);   // close the socket, and do any other cleanup needed
  CFRunLoopRef currentRunLoop = CFRunLoopGetCurrent();
  CFRunLoopRemoveSource(currentRunLoop, self.runLoop, kCFRunLoopCommonModes);
  if (splitPacketBuffer != NULL)
    free (splitPacketBuffer);
  splitPacketBuffer = NULL;
}

- (void)reconnect {
  struct allnet_log * alog = init_log ("ios xchat reconnect");
  p = init_pipe_descriptor(alog);
  self.sock = xchat_init ("xchat reconnect", NULL, p);
  CFSocketRef iOSSock = CFSocketCreateWithNative(NULL, self.sock, kCFSocketDataCallBack,
                                                 (CFSocketCallBack)&dataAvailable, NULL);
  // if you ever need to bind, use CFSocketSetAddress -- but not needed here
  self.runLoop = CFSocketCreateRunLoopSource(NULL, iOSSock, 100);
  CFRunLoopRef currentRunLoop = CFRunLoopGetCurrent();
  CFRunLoopAddSource(currentRunLoop, self.runLoop, kCFRunLoopCommonModes);
  NSLog (@"Xchat reconnect set socket to %d\n", self.sock);
}

- (int)getSocket {
  return self.sock;
}

struct request_key_arg {
  int sock;
  char * contact;
  char * secret1;
  char * secret2;
  int hops;
};
// invoked with lock held, releases the lock
static void * request_key (void * arg_void) {
  // now save the result
  struct request_key_arg * arg = (struct request_key_arg *) arg_void;
  waiting_for_key = 1;
  // next line will be slow if it has to generate the key from scratch
  create_contact_send_key(arg->sock, arg->contact, arg->secret1, arg->secret2, arg->hops);
  make_invisible(arg->contact);  // make sure the new contact is not (yet) visible
  waiting_for_key = 0;
  pthread_mutex_unlock(&key_generated_mutex);
  free(arg->contact);
  if (arg->secret1 != NULL)
    free (arg->secret1);
  if (arg->secret2 != NULL)
    free (arg->secret2);
  // NSLog(@"unlocked key generated mutex 2\n");
  printf ("finished generating and sending key\n");
  free (arg_void);  // we must free it
  return NULL;
}

- (void) requestNewContact:(NSString *)contact maxHops: (NSUInteger) hops
                   secret1:(NSString *) s1 optionalSecret2:(NSString *) s2
               keyExchange: (KeyExchangeUIViewController *) kev {
  pthread_mutex_lock(&key_generated_mutex);
  struct request_key_arg * arg =
  (struct request_key_arg *)malloc_or_fail(sizeof (struct request_key_arg), "request_key thread");
  arg->sock = self.sock;
  keyContact = strcpy_malloc (contact.UTF8String, "requestNewContact contact");
  arg->contact = strcpy_malloc (contact.UTF8String, "requestNewContact contact");
  arg->secret1 = NULL;
  arg->secret2 = NULL;
  if ((s1 != nil) && (s1 != NULL) && (s1.length > 0)) {
    arg->secret1 = strcpy_malloc (s1.UTF8String, "requestNewContact secret");
    normalize_secret(arg->secret1);
  }
  if ((s2 != nil) && (s2 != NULL) && (s2.length > 0)) {
    arg->secret2 = strcpy_malloc (s2.UTF8String, "requestNewContact secret2");
    normalize_secret(arg->secret2);
  }
  arg->hops = (int)hops;
  self.keyExchange = kev;
  //create_contact_send_key(self.sock, keyContact, keySecret, keySecret2, (int)hops);
  pthread_t thread;
  pthread_create(&thread, NULL, request_key, (void *) arg);
}

- (void)requestKey:(NSString *)contact maxHops: (NSUInteger) hops {
  if (! subscribe_broadcast(self.sock, (char *) (contact.UTF8String)))
    printf ("subscription to %s failed\n", contact.UTF8String);
}

static void dataAvailable (CFSocketRef s, CFSocketCallBackType callbackType, CFDataRef address,
                           const void * dataVoid, void * info) {
  // static pthread_mutex_t packet_mutex = PTHREAD_MUTEX_INITIALIZER;
  if (dataVoid == NULL)
    return;
  CFDataRef data = (CFDataRef) ((char *)dataVoid);
  long signed_size =CFDataGetLength(data);
  if ((signed_size <= 0) || (signed_size >= UINT_MAX))
    return;
  unsigned int psize = (unsigned int)signed_size;
  char * dataChar = (char *)(CFDataGetBytePtr(data));
  // pthread_mutex_lock (&packet_mutex);
  int sock = CFSocketGetNative(s);
  splitPacket(sock, dataChar, psize);  /* does all the packet processing */
  // pthread_mutex_unlock (&packet_mutex);
}

static void splitPacket (int sock, char * data, unsigned int dlen)
{
  // NSLog(@"got packet of size %d\n", dlen);
  char ** messages = NULL;
  unsigned int * lengths = NULL;
  unsigned int * priorities = NULL;
  // NSLog(@"splitPacket calling split_messages (%p, %d, %p, %p, NULL, %p)\n", data, dlen, &messages, &lengths, &buffer);
  int n = split_messages (data, dlen, &messages, &lengths, &priorities, &splitPacketBuffer);
  // NSLog(@"splitPacket done calling split_messages\n");
  int ni;
  for (ni = 0; ni < n; ni++) {
    // NSLog(@"processing packet %d of size %d\n", ni, lengths [ni]);
    receiveFilterPacket(sock, messages [ni], lengths [ni], priorities [ni]);
  }
  if (messages != NULL)
    free (messages);
  if (lengths != NULL)
    free (lengths);
  if (priorities != NULL)
    free (priorities);
}

// limit the number of packets received, to avoid consuming too much CPU
// keep track of the packet processing time, and make sure it is no more than 10% (1/10) of the time
static void receiveFilterPacket (int sock, char * data, unsigned int dlen, unsigned int priority)
{
  // functionality has been moved to xcommon, receiveFilterPacket may be deleted
  receivePacket (sock, data, dlen, priority);
}

// main function to call handle_packet and process the results
static void receivePacket (int sock, char * data, unsigned int dlen, unsigned int priority)
{
  static int last_length = 0;
  if (dlen != last_length) {
    //NSLog(@"got %d\n", dlen);
    //printf ("got %d: ", dlen);
    last_length = dlen;
  }
  //int ptype = data[1];
  //printf ("%d", ptype);
  //NSLog(@"received data of length %d\n", psize);
  int verified, duplicate, broadcast;
  uint64_t seq;
  char * peer;
  keyset kset;
  char * desc;
  char * message;
  struct allnet_ack_info acks;
  acks.num_acks = 0;
  struct allnet_mgmt_trace_reply * trace = NULL;
  time_t mtime = 0;
  // if necessary, wait for the key to be generated before calling handle_packet
  pthread_mutex_lock(&key_generated_mutex);  // don't allow changes to keyContact until a key has been generated
  if ((! waiting_for_key) && (mySelf.keyExchange != nil)) {
    [mySelf.keyExchange notificationOfGeneratedKey:[[NSString alloc] initWithUTF8String:keyContact]];
    mySelf.keyExchange = nil;
  }
  // NSLog(@"calling handle_packet %d, %d bytes\n", sock, dlen);
  int mlen = handle_packet(sock, (char *)data, dlen, priority, &peer, &kset, &message, &desc,
                           &verified, &seq, &mtime, &duplicate, &broadcast, &acks, &trace);
  // NSLog(@"handle_packet completed, peer %p (%s), mlen %d\n", peer, peer, mlen);
  pthread_mutex_unlock(&key_generated_mutex);
  //printf (".%d/", mlen);
  if ((mlen > 0) && verified) {  // received a packet
    NSLog(@"mlen %d, verified %d, duplicate %d, broadcast %d, peer %s\n",
          mlen, verified, duplicate, broadcast, peer);
    NSString * contact = [[NSString alloc] initWithUTF8String:peer];
    if (! duplicate) {
      [mySelf.contacts newMessage:contact];
      AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
      NSString * msg = [[NSString alloc] initWithUTF8String:message];
      [appDelegate notifyMessageReceived:contact message:msg];
    }
    // NSLog(@"XChat.m: refreshed the conversation UI text view and the contacts UI table view\n");
  } else if (mlen == -1) {        // successfully exchanged keys
    NSLog(@"key exchange successfully completed for peer %s\n", keyContact);
    NSString * contact = [[NSString alloc] initWithUTF8String:keyContact];
    if ((mySelf.ncvcForNewContact != nil) && (mySelf.ncvcForNewContact.kev != nil))
      [mySelf.ncvcForNewContact.kev notificationOfCompletedKeyExchange:contact];
    else
      NSLog(@"XChat.m receivePacket, unable to notify null key exchange\n");
    pthread_mutex_lock(&key_generated_mutex);  // changing globals, forbid access for others that may also change them
    mySelf.keyExchange = nil;
    pthread_mutex_unlock(&key_generated_mutex);
  } else if (mlen == -2) {  // confirm successful subscription
      NSLog(@"got subscription %s\n", peer);
  }
  for (int i = 0; i < acks.num_acks; i++) {
//    NSLog(@"displaying ack sequence number %lld for peer %s, conversation %@\n", acks.acks[i], acks.peers[i], mySelf.conversation);
    printf ("displaying ack sequence number %lld for peer %s\n", acks.acks[i], acks.peers[i]);
    [mySelf.conversation markAsAcked:acks.peers[i] ackNumber:acks.acks[i]];
  }
}

- (void) removeNewContact: (NSString *) contact {
  const char * sContact = (char *)contact.UTF8String;
  delete_contact (sContact);
}

- (void) resendKeyForNewContact: (NSString *) contact {
  if (! waiting_for_key) {
    NSLog(@"resending key to %@\n", contact);
    resend_contact_key (self.sock, contact.UTF8String);
    NSLog(@"resent key to %@\n", contact);
  } else {
    NSLog(@"resend key for new contact %@: still generating key\n", contact);
  }
}

- (void) completeExchange: (NSString *) contact {
  const char * sContact = (char *)contact.UTF8String;
  keyset * keys = NULL;
  int nk = all_keys (sContact, &keys);
  for (int ik = 0; ik < nk; ik++)   // delete the exchange file, if any
    incomplete_exchange_file(sContact, keys [ik], NULL, NULL);
  make_visible(sContact);
}

- (void) unhideContact:(NSString *)contact {
  make_visible(contact.UTF8String);
}

// returns the contents of the exchange file, if any: hops\nsecret1\n[secret2\n]
- (NSString *) incompleteExchangeData: (NSString *) contact {
  const char * sContact = (char *)contact.UTF8String;
  keyset * keys = NULL;
  int nk = all_keys (sContact, &keys);
  for (int ik = 0; ik < nk; ik++) {  // delete the exchange file, if any
    char * contents = NULL;
    incomplete_exchange_file(sContact, keys [ik], &contents, NULL);
    if (contents != NULL) {
      NSString * result = [[NSString alloc] initWithUTF8String:contents];
      free (contents);
      return result;
    }
  }
  return nil;
}

- (NSString *) trace: (BOOL)wide maxHops: (NSUInteger) hops {
  extern char * trace_string (const char * tmp_dir, int sleep, const char * dest, int nhops, int no_intermediates, int match_only, int wide);
  int cWide = 0;   // a C boolean is an int
  if (wide)
    cWide = 1;
  // NSLog(@"wide is %hhd %d\n", wide, cWide);
  NSString * tmpDir = NSTemporaryDirectory();
  char * string = trace_string(tmpDir.UTF8String, 5, NULL, (int)hops, 1, 0, cWide);
  NSString * result = [[NSString alloc] initWithUTF8String:string];
  free (string);
  return result;
}

struct trace_thread_args {
  int sock;
  int wide;
  int hops;
  int no_intermediates;
};

static void * async_trace (void * arg)
{
  struct trace_thread_args a = *(struct trace_thread_args *) arg;
  free (arg);
  trace_pipe (a.sock, NULL, -1, NULL, a.hops, a.no_intermediates, 0, a.wide);
  return NULL;
}

static void (* global_receive_function) (const char *) = NULL;

static void traceResult (CFSocketRef s, CFSocketCallBackType callbackType, CFDataRef address, const void * dataVoid, void * info) {
  CFDataRef data = (CFDataRef) ((char *)dataVoid);
  int psize = (int)CFDataGetLength(data);
  char * dataChar = (char *)(CFDataGetBytePtr(data));
  int last = 0;
  if (psize > 0)
    print_buffer(dataChar, psize, "trace result", 100, 1);
  for (int i = 0; i < psize; i++) {
    if (dataChar [i] == '\0') {
      NSLog(@"traceResult received %d-byte data\n", i);
      if (i > last)
        printf ("traceResult got %s\n", dataChar + last);
      if (global_receive_function != NULL)  // data is null-terminated
        global_receive_function (dataChar + last);
      else if (i > last)
        NSLog(@"traceResult received %d-byte unterminated data\n", psize);
      last = i + 1;
      
    }
  }
}

// used as an alternative to trace.  result lines are given to the function as they arrive
- (void) startTrace: (void (*) (const char *)) rcvFunction wide: (int) wide_enough maxHops: (NSUInteger) hops showDetails: (BOOL) details {
  global_receive_function = rcvFunction;
  int pipes [2];
  if (socketpair(AF_LOCAL, SOCK_STREAM, 0, pipes) != 0) {
    perror ("socketpair");
    NSLog (@"startTrace unable to open socket pair\n");
    return;
  }
#ifdef SETSOCKOPT_SUPPORTED_BY_IOS
  int option = 1;  /* disable Nagle algorithm */
  if (setsockopt (pipes [0], IPPROTO_TCP, TCP_NODELAY,
                  &option, sizeof (option)) != 0) {
    perror ("setsockopt");
    printf ("unable to set nodelay TCP socket option for trace pipe 0\n");
  }
  if (setsockopt (pipes [1], IPPROTO_TCP, TCP_NODELAY,
                  &option, sizeof (option)) != 0)
    printf ("unable to set nodelay TCP socket option for trace pipe 1\n");
#endif /* SETSOCKOPT_SUPPORTED_BY_IOS */
  
  CFSocketRef iOSSock = CFSocketCreateWithNative(NULL, pipes [0], kCFSocketDataCallBack,
                                                 (CFSocketCallBack)&traceResult, NULL);
  CFRunLoopSourceRef runLoop = CFSocketCreateRunLoopSource(NULL, iOSSock, 100);
  CFRunLoopRef currentRunLoop = CFRunLoopGetCurrent();
  CFRunLoopAddSource(currentRunLoop, runLoop, kCFRunLoopCommonModes);
  pthread_t tid;
  struct trace_thread_args * arg = malloc_or_fail(sizeof (struct trace_thread_args), "startTrace");
  arg->sock = pipes [1];
  arg->wide = wide_enough;
  arg->hops = (int)hops;
  arg->no_intermediates = ((details) ? 0 : 1);
  pthread_create (&tid, NULL, async_trace, arg);
  /* pthread_join(tid, NULL); */
}

@end
