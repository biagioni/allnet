//
//  NewContactViewController.h
//  xchat UI
//
//  Created by e on 2015/04/25.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "KeyExchangeUIViewController.h"

@interface NewContactViewController : UIViewController<UIPickerViewDataSource, UIPickerViewDelegate, UIScrollViewDelegate>

@property (weak, nonatomic) IBOutlet UIPickerView *contactTypePicker;
@property (weak, nonatomic) IBOutlet UIButton *contactGoButton;
@property (weak, nonatomic) IBOutlet UITextField *contactName;
@property (weak, nonatomic) IBOutlet UITextField *contactSecret;

@property (weak, nonatomic) IBOutlet UILabel *incompleteExchanges;
@property (weak, nonatomic) IBOutlet UISegmentedControl *incompleteContacts;

@property (weak, nonatomic) KeyExchangeUIViewController *kev;  // only set when we prepare for the segue

@end

