//
//  AppDelegate.h
//  xchat UI
//
//  Created by e on 2015/04/25.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "XChat.h"
#import "ConversationUITextView.h"
#import "ContactsUITableViewController.h"

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property XChat * xChat;
@property ConversationUITextView * conversation;
@property ContactsUITableViewController * tvc;

@property UIApplication * my_app;

- (void) setXChatValue:(XChat *)xChat;
- (void) setConversationValue:(ConversationUITextView *)conversation;
- (void) setContactsUITVC: (ContactsUITableViewController *) tvc;
- (void) batteryChangedNotification;
- (void) notifyMessageReceived:(NSString *) contact message: (NSString *) msg;
- (BOOL) appIsInForeground;

@end

