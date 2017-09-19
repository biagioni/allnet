//
//  XChatSocket.h
//  xchat UI
//
//  Created by e on 2015/05/22.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#ifndef xchat_UI_XChat_h
#define xchat_UI_XChat_h

#import "ConversationUITextView.h"
#import "ContactsUITableViewController.h"
#import "NewContactViewController.h"
#import "MoreUIViewController.h"

@interface XChat : NSObject

// - (void) initialize: (ConversationUITextView *) conversation contacts: (ContactsUITableViewController *) contacts vc: (NewContactViewController *) vcForNewContact;
- (void) initialize: (ConversationUITextView *) conversation contacts: (ContactsUITableViewController *) contacts vc: (NewContactViewController *) vcForNewContact mvc: (MoreUIViewController *) mvc;
- (void) disconnect;
- (void) reconnect;

- (void) requestNewContact:(NSString *)contact
                   maxHops:(NSUInteger) hops
                   secret1:(NSString *) s1
           optionalSecret2:(NSString *) s2
               keyExchange:(KeyExchangeUIViewController *) kev;

- (void) requestKey:(NSString *)contact maxHops: (NSUInteger) hops;

- (int) getSocket;

- (void) removeNewContact: (NSString *) contact;
- (void) resendKeyForNewContact: (NSString *) contact;
- (NSString *) trace: (BOOL)wide maxHops: (NSUInteger) hops;
- (void) startTrace: (void (*) (const char *)) rcvFunction wide: (int) wide_enough maxHops: (NSUInteger) hops showDetails: (BOOL) details;

- (void) completeExchange: (NSString *) contact;
// returns the contents of the exchange file, if any: hops\nsecret1\n[secret2\n]
- (NSString *) incompleteExchangeData: (NSString *) contact;
- (void) unhideContact: (NSString *) contact;

@end


#endif
