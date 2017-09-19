//
//  SettingsViewController.h
//  allnet-xchat
//
//  Created by e on 2016/07/05.
//  Copyright © 2016 allnet. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface SettingsViewController : UIViewController

@property const char * contact;

// call before transferring control to the settings view
- (void) initialize: (const char *)contact;

@end
