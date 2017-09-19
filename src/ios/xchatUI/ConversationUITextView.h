//
//  ConversationUITextView.h
//  xchat UI
//
//  Created by e on 2015/06/14.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ConversationUITextView : UITextView

- (void)initialize: (int) sock messageField: (UITextView *) message sendButton: (UIButton*) button contact: (NSString *) contact decorativeLabel: (UILabel *)newMessageLabel;

- (void) setSocket: (int) sock;

- (void)displayContact: (NSString *) contact;

- (void)markAsAcked: (const char *) contact ackNumber: (long long int) ack;

// return the contact name we are currently displaying, or null if no contact or not displayed
- (NSString *)selectedContact;

@property char * xcontact;

@end
