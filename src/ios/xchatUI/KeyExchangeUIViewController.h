//
//  KeyExchangeUIViewController.h
//  xchat UI
//
//  Created by e on 2015/07/13.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface KeyExchangeUIViewController : UIViewController

// groupCreated is only valid if isGroup is YES
- (void) initializeWindow:(NSString *) contact secret1: (NSString *) s1 secret2: (NSString *) s2 isGroup:(BOOL)isGroup alreadyCreated:(BOOL)created;

- (void) notificationOfCompletedKeyExchange: (NSString *) contact;
- (void) notificationOfGeneratedKey: (NSString *) contact;

@end
