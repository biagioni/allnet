//
//  NewContactViewController.m
//  xchat UI
//
//  Created by e on 2015/04/25.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import "AppDelegate.h"
#import "NewContactViewController.h"
#import "XChat.h"
#import "KeyExchangeUIViewController.h"

#include "lib/util.h"
#include "xchat/cutil.h"

@interface NewContactViewController ()

@property NSArray * selectionArray;
@property NSInteger selected;
@property NSSet * selectionTarget;
@property NSString * contactGeneratedSecret;
@property UIScrollView * scrollView;
@property BOOL keyboardIsDisplayed;
@property int originalFrameHeight;  // zero if keyboard was never displayed
@property int keyboardHeight;       // only valid if keyboardIsDisplayed

@end

@implementation NewContactViewController

#define TAG_CONTACT_NAME      1
#define TAG_CONTACT_SECRET    2
#define TAG_GO_BUTTON         3
#define TAG_INCOMPLETE_LABEL  4

static char ** incompletes = NULL;
static int num_incompletes = 0;

- (void)viewDidLoad {
  // NSLog(@"new contact view controller: calling super\n");
  [super viewDidLoad];
  // Do any additional setup after loading the view, typically from a nib.
  // NSLog(@"new contact view controller: view controllers has %@, picker has %@\n", self.tabBarController.viewControllers, self.contactTypePicker);
  // self.selectionArray = @[@"regular internet contact", @"nearby wireless contact", @"subscribe to a broadcast"];
  // self.selectionArray = @[@"regular internet contact", @"nearby wireless contact"];
  self.selectionArray = @[@"regular internet contact", @"nearby wireless contact", @"new group"];
  self.selected = 0;   // default
  self.selectionTarget = nil;
  // initialize the picker to specify the type of contact
  self.contactTypePicker.dataSource = self;
  self.contactTypePicker.delegate = self;
  // initialize the go button
  self.kev = nil;
  self.keyboardIsDisplayed = NO;
  self.originalFrameHeight = 0;
  self.keyboardHeight = 0;
  self.scrollView = nil;
  self.contactGoButton = nil;
  self.incompleteExchanges = nil;
  self.incompleteContacts = nil;
  // figure out how to watch the contact name field so we re-enable the go button when a valid (non-existing) contact name is entered
  for (NSObject * item in self.view.subviews) {
    // NSLog(@"ConversationViewController view.subview %@\n", item);
    if ([item isKindOfClass: [UIScrollView class]]) {
      self.scrollView = (UIScrollView *) item;
      for (NSObject * scrollItem in self.scrollView.subviews) {
        if ([scrollItem isKindOfClass:[UILabel class]]) {
          UILabel * label = (UILabel *) scrollItem;
          if (label.tag == TAG_INCOMPLETE_LABEL) {
            [label setHidden:YES];
            self.incompleteExchanges = label;
          }
        } else if ([scrollItem isKindOfClass:[UISegmentedControl class]]) {
          self.incompleteContacts = (UISegmentedControl *) scrollItem;
          [self.incompleteContacts setHidden:YES];
          // NSLog(@"found incompleteContacts\n");
        } else if ([scrollItem isKindOfClass:[UITextField class]]) {
          UITextField * field = (UITextField *) scrollItem;
          if (field.tag == TAG_CONTACT_NAME) {
            self.contactName = field;
            // initialize the text message field for sending messages
            [field addTarget:self action:@selector(contactEntered:) forControlEvents:UIControlEventAllEditingEvents]; // UIControlEventEditingDidEndOnExit];
          } else if (field.tag == TAG_CONTACT_SECRET) {
            self.contactSecret = field;
          }
        } else if ([scrollItem isKindOfClass:[UIButton class]]) {
          UIButton * button = (UIButton *) scrollItem;
          NSLog (@"found button %@\n", button);
          if (button.tag == TAG_GO_BUTTON) {
            self.contactGoButton = button;
            [button addTarget:self action:@selector(goButtonClicked:)
             forControlEvents:UIControlEventTouchUpInside];
            [button setEnabled:NO];   // disable until we have useful data
          }
        }
      }
    }
  }
  // NSLog (@"new contact view controller: sv is %@, ic is %@ %@, contact is %@ %@ %@\n", self.scrollView, self.incompleteContacts, self.incompleteExchanges, self.contactName, self.contactSecret, self.contactGoButton);
  num_incompletes = incomplete_key_exchanges (&incompletes, NULL, NULL);
  if ((num_incompletes > 0) && (self.incompleteExchanges != nil) && (self.incompleteContacts != nil)) {
    NSLog(@"found %d incomplete key exchanges\n", num_incompletes);
    [self.incompleteExchanges setHidden:NO];
    [self.incompleteContacts setHidden:NO];
    [self.incompleteContacts removeAllSegments];
    for (int ii = num_incompletes - 1; ii >= 0; ii--) {
      NSLog(@"  %s\n", incompletes [ii]);
      NSString * title = [[NSString alloc] initWithUTF8String:incompletes[ii]];
      [self.incompleteContacts insertSegmentWithTitle:title atIndex:0 animated:NO];
      [self.incompleteContacts setHidden:NO];
      [self.incompleteContacts addTarget:self action:@selector(incompleteSegmentButtonClicked:) forControlEvents:UIControlEventValueChanged];
    }
    // [self.contactGoButton setEnabled:YES];   // allow going to incomplete exchange(s)
  }
  NSLog(@"scroll view is %@\n", self.scrollView);
  [self enableContactGoButton];
  //NSURL*url = [[NSBundle mainBundle] URLForResource:@"contacts" withExtension:@""];
  // register for notifications that the keyboard is being displayed
  [[NSNotificationCenter defaultCenter] addObserver:self
                                           selector:@selector(readyToShowKeyboard:)
                                               name:UIKeyboardDidShowNotification//UIKeyboardWillShowNotification
                                             object:nil];
  // register for notifications that the keyboard is being hidden
  [[NSNotificationCenter defaultCenter] addObserver:self
                                           selector:@selector(readyToHideKeyboard:)
                                               name: UIKeyboardWillHideNotification
                                             object:nil];
}

- (void) enableContactGoButton {
  UITextField * textField = self.contactName;
  NSLog(@"new contact name is %@\n", textField.text);
  if ((textField.text.length > 0) && (num_keysets(textField.text.UTF8String) <= 0)) {
    [self.contactGoButton setEnabled:YES];
  } else {
    BOOL enable = NO;
    if ((! self.incompleteExchanges.hidden) && (! self.incompleteContacts.hidden) &&
        (self.incompleteContacts.selectedSegmentIndex >= 0) &&
        (self.incompleteContacts.selectedSegmentIndex < num_incompletes))
      enable = YES;
    [self.contactGoButton setEnabled:enable];
  }
}

- (IBAction)contactEntered:(id)sender {
  [self enableContactGoButton];
}

- (IBAction)incompleteSegmentButtonClicked:(id)sender {
  NSLog(@"incompleteSegmentButtonClicked, sender is %@\n", sender);
  [self enableContactGoButton];
}

- (void)didReceiveMemoryWarning {
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
  NSLog(@"received memory warning\n");
}

// number of columns of data
- (NSInteger)numberOfComponentsInPickerView:(UIPickerView *)pickerView
{
  return 1;
}

// number of columns of data
- (NSInteger)pickerView:(UIPickerView *)pickerView numberOfRowsInComponent:(NSInteger)component
{
  return self.selectionArray.count;
}

- (NSString *)pickerView:(UIPickerView *)pickerView titleForRow:(NSInteger)row forComponent:(NSInteger)component
{
  return self.selectionArray[row];
}

- (void)viewWillAppear:(BOOL)Animated {
  [super viewWillAppear: Animated];
  // NSLog(@"\nnew contact view controller: view will appear\n\n");
}

- (void)pickerView:(UIPickerView *)pickerView didSelectRow:(NSInteger)row inComponent:(NSInteger)component
{
  int wasSelected = (int)self.selected;
  NSLog(@"selected row %d, was %d\n", (int) row, wasSelected);
  self.selected = row;
  if (row == 0)
    NSLog(@"new contact is at a distance\n");
  else if (row == 1)
    NSLog(@"new contact is in wireless range\n");
  else if (row == 2)
    NSLog(@"new contact is a group\n");
  else
    NSLog(@"subscribing");
}

- (void) createRequest: (KeyExchangeUIViewController *) destination
{
  // NSLog(@"new contact view controller: createRequest called\n");
  AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
  XChat * socket = appDelegate.xChat;
  if ((self.selected == 0) || (self.selected == 1)) {  // exchanging keys
    int hops = 6;
    if (self.selected == 1) {  // in local wireless range
      hops = 1;
      // self.contactGeneratedSecret = [self.contactGeneratedSecret substringToIndex:6];
    }
    NSLog(@"createRequest (%@, %d, %@, %@)\n", self.contactName.text, hops, self.contactGeneratedSecret, self.contactSecret.text);
    [socket requestNewContact:self.contactName.text
                      maxHops:hops
                      secret1:self.contactGeneratedSecret
              optionalSecret2:self.contactSecret.text
                  keyExchange:destination];
  } else if (self.selected == 2) {  // create group
    NSLog(@"should create group %@\n", self.contactName.text);
  } else {  // request key
    [socket requestKey:self.contactName.text maxHops: 10];
  }
}

- (IBAction)goButtonClicked:(id)sender
{
  NSLog(@"clicked, text fields are '%@' and '%@', generated secret %@, self.selected %d\n", self.contactName.text, self.contactSecret.text, self.contactGeneratedSecret, (int)self.selected);
  // we now create the request in prepareForSegue, so it is after initializing the window.
  // that is important because otherwise the reply might be received before the window is
  // set up, and the window code in KeyExchangeViewController.m/initializeWindow can't handle that
  //[self createRequest];
}

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender
{
  NSLog(@"in prepareForSegue in NewContactViewController.m, segue %@/%p\n", segue.identifier, segue);
  NSLog(@"segue destination is %@\n", [segue destinationViewController]);
  NSLog(@"segue contact '%@', secrets '%@' and '%@', self.selected %d\n", self.contactName.text, self.contactSecret.text, self.contactGeneratedSecret, (int)self.selected);
  NSString * contactName = nil;
  NSString * enteredSecret = nil;
  NSString * randomSecret = nil;
  BOOL created = NO;
  int hopsCount = 0;
  if ((self.contactName != nil) && (self.contactName.text != nil) && (self.contactName.text.length > 0)) {
    contactName = self.contactName.text;
    if ((self.contactSecret != nil) && (self.contactSecret.text != nil) && (self.contactSecret.text.length > 0))
      enteredSecret = self.contactSecret.text;
  }
  if ((contactName == nil) && (self.incompleteContacts.numberOfSegments > 0) &&
      (self.incompleteContacts.selectedSegmentIndex >= 0) &&
      (self.incompleteContacts.selectedSegmentIndex < num_incompletes) &&
      (self.incompleteContacts.numberOfSegments > self.incompleteContacts.selectedSegmentIndex)) {
    char * contact = incompletes [self.incompleteContacts.selectedSegmentIndex];
    NSLog (@"incompletes [%ld] is %s\n", (long)self.incompleteContacts.selectedSegmentIndex, contact);
    contactName = [[NSString alloc] initWithUTF8String:contact];
    keyset * keys = NULL;
    int nk = all_keys (contact, &keys);
    for (int ki = 0; ki < nk; ki++) {
      char * s1 = NULL;
      char * s2 = NULL;
      char * content = NULL;
      incomplete_exchange_file(contact, keys [ki], &content, NULL);
      NSLog (@"incomplete content for %s %d (%d/%d) is '%s'\n", contact, keys [ki], ki, nk, content);
      if (content != NULL) {
        char * first = index (content, '\n');
        if (first != NULL) {
          *first = '\0';  // null terminate hops count
          hopsCount = atoi (content);  // ignore any errors
          s1 = first + 1;
          char * second = index (s1, '\n');
          if (second != NULL) {
            *second = '\0';  // null terminate first secret
            s2 = second + 1;
            char * third = index (s2, '\n');
            if (third != NULL) // null terminate second secret
              *third = '\0';
            if (*s2 == '\0')
              s2 = NULL;
            NSLog (@"first %s, second %s, third %s, s1 %s, s2 %s\n", first, second, third, s1, s2);
          }
        }  // do the assignments before freeing content, since s1 and s2 point to content
        if (s1 != NULL)
          randomSecret = [[NSString alloc] initWithUTF8String:s1];
        if (s2 != NULL)
          enteredSecret = [[NSString alloc] initWithUTF8String:s2];
        if (hopsCount != 0) {
          if (hopsCount == 1)
            self.selected = 1;
          else if (hopsCount == 6)
            self.selected = 0;
        }
        free (content);
        allnet_rsa_pubkey pk;
        if (get_contact_pubkey(keys [ki], &pk) > 0)
          created = YES;
        NSLog(@"contact %s, found saved secrets %@ %@, hop count %d, created %d\n",
              contact, randomSecret, enteredSecret, hopsCount, created);
        break;  // found, exit the loop
      }
    }
    if (keys != NULL)
      free (keys);
  }
  if (contactName == nil) {
    NSLog (@"bad contact name, incomplete %@ %ld/%ld %d:%d, prepareForSegue returning\n", self.incompleteContacts, (long)self.incompleteContacts.selectedSegmentIndex, (long)self.incompleteContacts.numberOfSegments, self.incompleteContacts.selected, self.incompleteContacts.isSelected);
    return;
  }

#define MAX_RANDOM  15   // 14 characters plus a null character
  char randomString [MAX_RANDOM];
  if (randomSecret == nil) {
    random_string(randomString, MAX_RANDOM);
    normalize_secret(randomString);
    self.contactGeneratedSecret = nil;
    if ((self.selected == 0) || (self.selected == 1)) {
      self.contactGeneratedSecret = [[NSString alloc] initWithUTF8String:randomString];
      if (self.selected == 1)
        self.contactGeneratedSecret = [self.contactGeneratedSecret substringToIndex:6];
    }
    randomSecret = self.contactGeneratedSecret;
  }
  // set the variables used by createRequest
  [self.contactName setText:contactName];
  self.contactGeneratedSecret = randomSecret;
  if (enteredSecret != nil)
    [self.contactSecret setText:enteredSecret];
  else
    [self.contactSecret setText:@""];
  NSObject * destinationObject = [segue destinationViewController];
  if ([destinationObject isMemberOfClass:[KeyExchangeUIViewController class]]) {
    self.kev = (KeyExchangeUIViewController *) destinationObject;
    BOOL createGroup = (self.selected == 2);
    if (createGroup)
      created = create_group (contactName.UTF8String);
    NSLog(@"calling initializeWindow %@ %@ %@, selected %d, created %d\n", contactName, randomSecret, enteredSecret, (int)self.selected, created);
    [self.kev initializeWindow:contactName secret1:randomSecret secret2:enteredSecret isGroup:createGroup alreadyCreated:created];
    [self createRequest: self.kev];
  }
}

- (void)readyToShowKeyboard:(NSNotification *)notification {
  NSLog(@"NewContactViewController ready to show keyboard\n");
  if (self.keyboardIsDisplayed)
    return;
  NSDictionary* userInfo = [notification userInfo];
  
  // get the height of the keyboard
  int keyboardHeight = [[userInfo objectForKey:UIKeyboardFrameBeginUserInfoKey]
                        CGRectValue].size.height;
  NSLog(@"keyboard height is %d, y is %d, height %d\n", keyboardHeight, (int)(self.scrollView.frame.origin.y), (int)(self.scrollView.frame.size.height));
  // check out http://stackoverflow.com/questions/1126726/how-to-make-a-uitextfield-move-up-when-keyboard-is-present/21096604#21096604
  CGRect scrollViewFrame = self.scrollView.frame;
  NSLog(@"initial view frame %f %f %f %f\n", scrollViewFrame.origin.x, scrollViewFrame.origin.y, scrollViewFrame.size.width, scrollViewFrame.size.height);
  self.originalFrameHeight = scrollViewFrame.size.height;
  self.keyboardHeight = keyboardHeight;
  if (scrollViewFrame.size.height > keyboardHeight)
    scrollViewFrame.size.height -= keyboardHeight;
  else
    scrollViewFrame.size.height = 0;
  // NSLog (@"frame height %d -> %d\n", self.originalFrameHeight, (int)scrollViewFrame.size.height);
  [self.scrollView setFrame:scrollViewFrame];
  scrollViewFrame.size.height = self.originalFrameHeight;
  [self.scrollView setContentSize:scrollViewFrame.size];
  // NSLog (@"frame height %d -> %d, sv %@\n", self.originalFrameHeight, (int)scrollViewFrame.size.height, self.scrollView);
  
  self.keyboardIsDisplayed = YES;
  NSLog(@"newcontact set scroll view frame to %f %f %f %f, %@\n", scrollViewFrame.origin.x, scrollViewFrame.origin.y, scrollViewFrame.size.width, scrollViewFrame.size.height, self.scrollView);
}

- (void)readyToHideKeyboard:(NSNotification *)notification {
  NSLog(@"NewContactViewController ready to hide keyboard\n");
  if (! self.keyboardIsDisplayed)
    return;
  CGRect scrollViewFrame = self.scrollView.frame;
  scrollViewFrame.size.height = self.originalFrameHeight;
  [self.scrollView setFrame:scrollViewFrame];
  NSLog(@"hiding keyboard, original frame height %d, set frame to %f %f %f %f, sv %@\n", self.originalFrameHeight, scrollViewFrame.origin.x, scrollViewFrame.origin.y, scrollViewFrame.size.width, scrollViewFrame.size.height, self);
  self.keyboardIsDisplayed = NO;
}

@end
