//
//  ContactsUITableViewController.h
//  xchat UI
//
//  Created by e on 2015/05/05.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ContactsUITableViewController : UITableViewController<UIScrollViewDelegate>

// when the interface is displayed, note that this contact has a new message
- (void) newMessage: (NSString *) contact;

// let this UI know that the conversation is being displayed or hidden, so we know whether messages are read or unread
- (void) notifyConversationChange: (BOOL) beingDisplayed;

@end
