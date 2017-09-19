//
//  KeyExchangeUIViewController.m
//  xchat UI
//
//  Created by e on 2015/07/13.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import "KeyExchangeUIViewController.h"
#import "AppDelegate.h"
#import "XChat.h"

@interface KeyExchangeUIViewController ()

@property UIButton * cancelButton;
@property UIButton * resendButton;
@property UIButton * backButton;
@property NSString * contactName;

@property UILabel * exchangingWith;
@property UITextView * secretView;
@property UITextView * progressView;

@property BOOL keyExchangeCompleted;

@end


@implementation KeyExchangeUIViewController

- (void) viewDidLoad {
  [super viewDidLoad];
  if (self.cancelButton != nil)
    [self.cancelButton addTarget:self action:@selector(cancelButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
  if (self.resendButton != nil)
    [self.resendButton addTarget:self action:@selector(resendButtonClicked:)forControlEvents:UIControlEventTouchUpInside];
}

// groupCreated is only valid if isGroup is YES
- (void) initializeWindow:(NSString *) contact secret1: (NSString *) s1 secret2: (NSString *) s2 isGroup:(BOOL)isGroup alreadyCreated:(BOOL)created
// - (void) initializeWindow:(NSString *) contact secret1: (NSString *) s1 secret2: (NSString *) s2 group: (BOOL)g
{
  self.cancelButton = nil;
  self.resendButton = nil;
  self.backButton = nil;
  self.secretView = nil;
  self.progressView = nil;
  self.contactName = contact;
  self.exchangingWith = nil;
  self.keyExchangeCompleted = (isGroup || created);   // no key exchange for groups
  UIView * v = self.view;
  NSArray * subviews = v.subviews;
  // NSLog(@"subviews are %@\n", subviews);
  for (NSObject * item in subviews) {  // create self.message first, used in self.conversation initialize
    // NSLog(@"subview %@\n", item);
    if ([item isMemberOfClass: [UITextView class]]) {  // secretView has a tag of 10, progressView 11
      UITextView * tv = (UITextView *) item;
      // NSLog(@"found text view %@, color %@\n", tv.text, tv.backgroundColor);
        if (tv.tag == 10) {
          self.secretView = tv;
          if (isGroup)   // it's a group, no key exchange
            self.secretView.text = [[NSString alloc] initWithFormat:@""];
          else if ((s2 == nil) || (s2.length < 1))
            self.secretView.text = [[NSString alloc] initWithFormat:@"Shared secret:\n%@", s1];
          else
            self.secretView.text = [[NSString alloc] initWithFormat:@"Shared secret:\n%@\nor:\n%@", s1, s2];
        } else if (tv.tag == 11) {
          self.progressView = tv;
          if (isGroup) {
            if (created) {
              self.progressView.text = [[NSString alloc] initWithFormat:@"Created group '%@'\n", contact];
              self.progressView.backgroundColor = UIColor.greenColor;
            } else { // creation failed
              self.progressView.text = [[NSString alloc] initWithFormat:@"unable to create group '%@'\n", contact];
            }
          } else {
            self.progressView.text = [self.progressView.text stringByAppendingString:contact];
            if (created) {
              self.progressView.backgroundColor = UIColor.greenColor;
              self.progressView.text = @"Key received successfully";
            }
          }
        }
     
    } else if ([item isMemberOfClass:[UIButton class]]) {
      UIButton * button = (UIButton *) item;
      NSLog(@"found button %@/%@\n", button, button.titleLabel);
      if (button.tag == 1) {  // "resend key"
        self.resendButton = button;
        [button setTitle:@"resend key" forState:UIControlStateNormal];
        [button setHidden:isGroup];  // no key exchange for groups, so don't resend
        if (! isGroup)
          [self.resendButton addTarget:self action:@selector(resendButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
      } else if (button.tag == 2) { // "cancel"
        self.cancelButton = button;
        [button setTitle:@"cancel" forState:UIControlStateNormal];
        if (created)
          [button setTitle:@"done" forState:UIControlStateNormal];
        else
          [self.cancelButton addTarget:self action:@selector(cancelButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
      } else if (button.tag == 3) { // "back"
        self.backButton = button;
        if (created)
          [self.backButton setHidden:YES];
        // [self.backButton addTarget:self action:@selector(backButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
      }
    } else if ([ item isMemberOfClass:[UILabel class]]) {
      self.exchangingWith = (UILabel *) item;
      if (isGroup && created)
        [self.exchangingWith setText:@"done creating group"];
      else if (isGroup)   // group creation failed
        [self.exchangingWith setText:@"unable to create group"];
      else if (created)   // key exchange complete
        [self.exchangingWith setText:[@"received key from " stringByAppendingString:contact]];
      else                // key exchange in progress
        [self.exchangingWith setText:[@"exchanging keys with: " stringByAppendingString:contact]];
      // NSLog(@"exchanging with %@\n", self.exchangingWith.text);
    }
  }
  NSLog(@"contact %@, secrets %@ and %@, buttons %@ and %@, views %@ and %@\n", contact, s1, s2, self.resendButton, self.cancelButton, self.secretView, self.progressView);
}

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
{
  NSLog(@"in prepareForSegue in KeyExchangeUIViewController.m, segue %@/%p\n", segue.identifier, segue);
  NSLog(@"contact name %@, segue destination is %@\n", self.contactName, [segue destinationViewController]);
}

- (void) notificationOfGeneratedKey: (NSString *) contact {
  if ([self.contactName isEqualToString:contact]) {
    // self.progressView.text = @"Key received successfully";
    // should replace "Generating key" with "Sent your key"
    NSLog(@"notified of key generation, text is %@\n", self.progressView.text);
    NSMutableString * replaceable = [[NSMutableString alloc] initWithString:self.progressView.text];
    NSRange all;
    all.location = 0;
    all.length = replaceable.length;
    [replaceable replaceOccurrencesOfString:@"Generating" withString:@"Sent" options:NSLiteralSearch range:all];
    self.progressView.text = [[NSString alloc] initWithUTF8String: replaceable.UTF8String];
    // NSLog(@"      new text is %@\n", self.progressView.text);
    [self.view setNeedsDisplay];
  }
  NSLog(@"KeyExchangeUIViewController.m notified of completed key generation with '%@', self '%@'\n", contact, self.contactName);
}

- (void) notificationOfCompletedKeyExchange: (NSString *) contact {
  if ([self.contactName isEqualToString:contact]) {
    NSLog(@"%@ isEqualToString %@\n", self.contactName, contact);
  }
  // this completes the exchange, so if the contact is hidden, make it visible
  AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
  XChat * socket = appDelegate.xChat;
  // signal that all is well
  self.keyExchangeCompleted = YES;
  self.progressView.backgroundColor = UIColor.greenColor;
  self.progressView.text = @"Key received successfully";
  self.secretView.text = @"";
  self.secretView.hidden = YES;    // hide the secret field
  [socket unhideContact:contact];  // and make sure the contact is visible
  self.exchangingWith.text = [[NSString alloc] initWithFormat:@"received key from %@\n", self.contactName];
  [self.cancelButton setTitle:@"done" forState:UIControlStateNormal];
  [self.view setNeedsDisplay];
  NSLog(@"KeyExchangeUIViewController.m notified of completed key xchg with '%@' (%lu), self '%@' (%lu)\n",
        contact, (unsigned long)contact.length, self.contactName, (unsigned long)self.contactName.length);
}

- (IBAction)cancelButtonClicked:(id)sender
{
  AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
  XChat * socket = appDelegate.xChat;
  if (self.keyExchangeCompleted) {
    NSLog(@"key exchange done button clicked\n");
    [socket completeExchange:self.contactName];
  } else {
    NSLog(@"cancel button clicked\n");
    [socket removeNewContact:self.contactName];
  }
}

- (IBAction)backButtonClicked:(id)sender
{
  AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
  XChat * socket = appDelegate.xChat;
  if (self.keyExchangeCompleted) {
    NSLog(@"key exchange back button clicked\n");
    [socket completeExchange:self.contactName];
  } else {
    NSLog(@"back button clicked\n");
  }
}

- (IBAction)resendButtonClicked:(id)sender
{
  NSLog(@"resend key button clicked\n");
  AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
  XChat * socket = appDelegate.xChat;
  [socket resendKeyForNewContact:self.contactName];
}

@end
