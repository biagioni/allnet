//
//  ConversationViewController.m
//  xchat UI
//
//  Created by e on 2015/07/06.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import "ConversationViewController.h"
#import "ConversationUITextView.h"
#import "SettingsViewController.h"

@interface ConversationViewController ()

@property ContactsUITableViewController * tvc;

@property UIScrollView * cvcScrollView;

@property ConversationUITextView * textView;

@end

// mostly needed so we know when the conversation is visible, so we can know whether a contact has new messages
// there may be an easier way to do this, but I don't know what that would be.

@implementation ConversationViewController

- (void)notifyChange: (ContactsUITableViewController *) contactsUI {
  self.tvc = contactsUI;
}

- (void)initTextViewFrame {
  // NSLog (@"initializing text view frame, currently %f %f, %f x %f, scroll view %@\n", self.textView.frame.origin.x, self.textView.frame.origin.y, self.textView.frame.size.width, self.textView.frame.size.height, self.cvcScrollView);
  CGRect textFrame;
  textFrame.origin.x = 0;
  textFrame.origin.y = 0;
  textFrame.size.height = TEXTVIEWSIZE;  // maximum allowed
  textFrame.size.width = self.cvcScrollView.frame.size.width;
  [self.textView setFrame:textFrame];
  CGPoint scrollOffset;
  scrollOffset.x = 0;
  scrollOffset.y = self.textView.frame.size.height - self.cvcScrollView.frame.size.height;
  // NSLog (@"initialized  text view frame, currently %f %f, %f x %f, scroll view %@\n", self.textView.frame.origin.x, self.textView.frame.origin.y, self.textView.frame.size.width, self.textView.frame.size.height, self.cvcScrollView);
}

- (void)initSubViews {
  self.cvcScrollView = nil;
  self.textView = nil;
  
  CGRect actualFrame = self.view.frame;
  // NSLog(@"view frame is %@\n", self.view);
  int viewWidth = actualFrame.size.width - 32;
  int viewHeight = actualFrame.size.height - 176;  // should be related to size of other windows
  for (NSObject * item in self.view.subviews) {
    // NSLog(@"ConversationViewController view.subview %@\n", item);
    if ([item isKindOfClass: [UIScrollView class]]) {
      self.cvcScrollView = (UIScrollView *) item;
    }
  }
  if (self.cvcScrollView != nil) {
    // NSLog(@"scroll view is %@\n", self.cvcScrollView);
    [self.cvcScrollView setFrame: actualFrame];
    CGRect scrollFrame = self.cvcScrollView.frame;
    scrollFrame.origin.x = 16;
    scrollFrame.origin.y = 73;   // reflects the position below the contact name
    scrollFrame.size.width = viewWidth;
    scrollFrame.size.height = viewHeight;
    [self.cvcScrollView setFrame: scrollFrame];
    NSArray * subviews = self.cvcScrollView.subviews;
    for (NSObject * item in subviews) {
      // NSLog(@"ConversationViewController cvcScrollView.subview %@\n", item);
      if ([item isMemberOfClass: [ConversationUITextView class]]) {
        self.textView = (ConversationUITextView *) item;
        [self initTextViewFrame];
      }
    }
    if ((self.cvcScrollView != nil) &&
        ([self.cvcScrollView isMemberOfClass: [ConversationUITextView class]])) {
      self.textView = (ConversationUITextView *) self.cvcScrollView;
      [self initTextViewFrame];
    }
    NSLog(@"scroll view is now %@\n", self.cvcScrollView);
    NSLog(@"%p: text view is now %@\n", self, self.textView);
  }
}

- (void)viewDidLoad {
  [super viewDidLoad];
  NSLog(@"\nConversationViewController view did load for %p, %@\n", self, self.view);
  [self initSubViews];
}

- (void)viewDidAppear:(BOOL)animated {
  [super viewDidAppear: animated];
  NSLog(@"\nConversationViewController view did appear for %@\n", self.view);
  // NSLog(@"child view controllers: %@\n", self.childViewControllers);
  // [self initSubViews];
  if (self.cvcScrollView != nil) {
    NSLog(@"self.cvcScrollView %@ subviews: %@\n", self.cvcScrollView, self.cvcScrollView.subviews);
    [self.cvcScrollView setScrollsToTop:NO];
    int offset = 0;
    if (self.cvcScrollView.contentSize.height > self.cvcScrollView.frame.size.height)
      offset = self.cvcScrollView.contentSize.height - self.cvcScrollView.frame.size.height;
    CGPoint endPoint = {0, offset};
    [self.cvcScrollView setContentOffset:endPoint];
  }
  if (self.tvc != nil)
    [self.tvc notifyConversationChange:YES];
}

- (void)viewDidDisappear:(BOOL)animated {
  [super viewDidDisappear:animated];
  //NSLog(@"\nview did disappear\n\n");
  if (self.tvc != nil)
    [self.tvc notifyConversationChange:YES];
}

#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
  // Get the new view controller using [segue destinationViewController].
  // Pass the selected object to the new view controller.
  //    NSLog (@"cvc preparing for segue to %@, sender %@, contact %s\n", [segue destinationViewController], sender, self.textView.xcontact);
  //    if ([[segue destinationViewController] isMemberOfClass:[SettingsViewController class]]) {
  //        NSLog (@"%p: self.textView is %@\n", self, self.textView);
  //        SettingsViewController * svc = (SettingsViewController *) [segue destinationViewController];
  //        [svc initialize:self.textView.xcontact];
  //    }
}

@end
