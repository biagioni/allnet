//
//  ContactsUITableViewController.m
//  xchat UI
//
//  Created by e on 2015/05/05.
//  Copyright (c) 2015 allnet. All rights reserved.
//

@import Foundation;

#import "AppDelegate.h"
#import "ContactsUITableViewController.h"
#import "XChat.h"
#import "ConversationUITextView.h"
#import "ConversationViewController.h"
#import "NewContactViewController.h"
#import "KeyExchangeUIViewController.h"
#import "MoreUIViewController.h"
#import "SettingsViewController.h"

// AllNet C includes
#include "packet.h"
#include "util.h"
#include "keys.h"
#include "store.h"

//#import "AddItemViewController.h"

@interface ContactsUITableViewController ()

@property NSMutableArray * contacts;
@property NSMutableArray * hiddenContacts;
@property NSMutableDictionary * contactsWithNewMessages;
@property XChat * xchat;
@property ConversationUITextView * conversation;
@property ConversationViewController * cvc;
@property NewContactViewController * mayCreateNewContact;  // objective C doesn't like names beginning with 'new'
@property MoreUIViewController * more;
@property UILabel * contactName;
@property UILabel * nMessageLabel;
@property UITextView * message;
@property UIButton * sendButton;
@property BOOL conversationIsDisplayed;
@property BOOL displaySettings;

@end

@implementation ContactsUITableViewController

#define NUM_HEADER_ROWS     4

- (IBAction)unwindToPlan:(UIStoryboardSegue *)segue {
  NSObject * source = [segue sourceViewController];
  NSLog(@"source in unwindToPlan is %@\n", source);
  // if added new contact, should add it to the list above
  //UILabel * item = source.item;
  // if (item != nil) {
  //    [self.items addObject:item];
  //    [self.tableView reloadData];
  // }
}

// initialize everything
- (void)viewDidLoad {
  NSLog(@"in ContactsUITableViewController, view did load");
  [super viewDidLoad];
  self.conversation = nil;
  self.xchat = [XChat alloc];
  self.contacts = [[NSMutableArray alloc] init];
  self.hiddenContacts = [[NSMutableArray alloc] init];
  self.contactsWithNewMessages = [[NSMutableDictionary alloc] init];
  [self setContacts];
  self.mayCreateNewContact = [self.tabBarController.viewControllers objectAtIndex:2];
  NSString * initialLatestContact = [self latestContact];
  self.conversationIsDisplayed = NO;
  self.displaySettings = NO;
  self.message = nil;
  self.sendButton = nil;
  
  self.cvc = [self.tabBarController.viewControllers objectAtIndex:1];
  [self.cvc notifyChange:self];   // register for notifications of window being displayed or not
  // NSLog(@"object is %@\n", self.cvc);
  NSArray * subviews = self.cvc.view.subviews;
  // NSLog(@"subviews are %@\n", subviews);
  for (NSObject * item in subviews) {  // create self.message first, used in self.conversation initialize
    // NSLog(@"subview %@\n", item);
    if ([item isMemberOfClass: [UITextView class]]) {
      self.message = (UITextView *) item;
      // NSLog (@"CTVC found message %@\n", item);
    } else if ([item isMemberOfClass: [UIButton class]]) {
      UIButton * button = (UIButton *) item;
      if (button.tag == 1)
        self.sendButton = button;
    }
  }
  if (self.message != nil) {
    for (NSObject * item in subviews) {
      if ([item isMemberOfClass: [ConversationUITextView class]]) {
        self.conversation = (ConversationUITextView *) item;
      } else if ([item isMemberOfClass: [UILabel class]]) {
        UILabel * label = (UILabel *) item;
        if (label.tag == 1)   // other labels must have different tags
          self.contactName = label;
        else if (label.tag == 2)
          self.nMessageLabel = label;
      } else if ([item isMemberOfClass: [MoreUIViewController class]]) {
        self.more = (MoreUIViewController *) item;
      }
    }
  }
  if (self.conversation != nil) {
    // NSLog(@"initializing xchat\n");
    [self.xchat initialize: self.conversation contacts:self vc:self.mayCreateNewContact mvc:self.more];  // initialize xchat, which creates the socket
    // now initialize the conversation, which requires the socket
    [self.conversation initialize:[self.xchat getSocket] messageField:self.message sendButton:self.sendButton
                          contact:initialLatestContact decorativeLabel:self.nMessageLabel];
    // finally, can give the xchat to the AppDelegate
    AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
    [appDelegate setXChatValue:self.xchat];
    [appDelegate setConversationValue:self.conversation];
    [appDelegate setTvc:self];
    // display the latest conversation, if any
  } else {
    NSLog(@"warning: failed to initialize xchat %@, exiting\n", self.xchat);
    exit (1);
  }
  if (initialLatestContact != nil) {
    // NSLog(@"initializing latest contact to '%@'\n", initialLatestContact);
    if (self.contactName == nil)
      self.contactName = [[UILabel alloc] init];
    self.contactName.text = initialLatestContact;
    [self.conversation displayContact:initialLatestContact];
  } else {
    NSLog(@"self.initialLatestContact is %@\n", initialLatestContact);
    self.contactName.text = @"no contact yet";
    [self.conversation displayContact:self.contactName.text];
  }
  
  //    NSLog(@"in ContactsUITableViewController, loaded initial data, initialized %@ %@ %@ %@\n", self.conversation, self.contactName, self.message, self.xchat);
  //  sleep (5);
  
  // Uncomment the following line to preserve selection between presentations.
  // self.clearsSelectionOnViewWillAppear = NO;
  
  // Uncomment the following line to display an Edit button in the navigation bar for this view controller.
  // self.navigationItem.rightBarButtonItem = self.editButtonItem;
}

- (void) reInitSocket {
  [self.conversation setSocket: [self.xchat getSocket]];
}

- (void) setContacts {
  [self loadInitialData];
}

- (NSString *) contactHeaderString:(NSUInteger)count :(BOOL)newMessages {
  NSString * contactsString = @"contacts";
  if (count == 1)
    contactsString = @"contact";
  if (newMessages)
    return [[NSString alloc] initWithFormat:@"%ld %@ with new messages", (unsigned long)count, contactsString];
  else
    return [[NSString alloc] initWithFormat:@"%ld %@ total", (unsigned long)count, contactsString];
}

- (NSMutableArray *) contactsHeader:(NSUInteger)contactsCount :(NSUInteger)contactsWithMessages {
  
  NSMutableArray * result = [[NSMutableArray alloc] initWithCapacity:4];
  [result addObject:@""];
  BOOL plural = (contactsWithMessages != 1);
  NSString * contactsString = @"contacts";
  if (! plural)
    contactsString = @"contact";
  NSString * contactsWith = [[NSString alloc] initWithFormat:@"%ld %@ with new messages",
                             (unsigned long)contactsWithMessages, contactsString];
  [result addObject:contactsWith];
  NSString * contactsTotal = [[NSString alloc] initWithFormat:@"%ld contacts total",
                              (unsigned long)contactsCount];
  [result addObject:contactsTotal];
  [result addObject:@""];
  return result;
}

- (void) loadInitialData {
  [self.contacts removeAllObjects];
  char ** contacts = NULL;
  int nc = all_contacts(&contacts);
  for (int ic = 0; ic < nc; ic++) {
    NSString * title = [[NSString alloc] initWithUTF8String: contacts[ic]];
    [self.contacts addObject:title];
    NSLog(@"found contact %@\n", title);
  }
  [self.contacts sortUsingFunction:contactCompare context:NULL];
  if (contacts != NULL)
    free (contacts);
  contacts = NULL;
  // repeat for hidden contacts
  [self.hiddenContacts removeAllObjects];
  nc = invisible_contacts(&contacts);
  for (int ic = 0; ic < nc; ic++) {
    NSString * title = [[NSString alloc] initWithUTF8String: contacts[ic]];
    [self.hiddenContacts addObject:title];
    NSLog(@"found contact %@\n", title);
  }
  [self.hiddenContacts sortUsingFunction:contactCompare context:NULL];
  if (contacts != NULL)
    free (contacts);
  return;
}

NSInteger contactCompare(NSString * contact1, NSString * contact2, void * context) {
  NSInteger time1 = lastTime(contact1, MSG_TYPE_RCVD);
  NSInteger time2 = lastTime(contact2, MSG_TYPE_RCVD);
  if (time1 > time2)
    return NSOrderedAscending;  // contact1 < contact2
  else if (time2 > time1)
    return NSOrderedDescending;
  else
    return NSOrderedSame;
}

NSInteger lastTime(NSString * objCContact, int msgType)
{
  char * contact = (char *) objCContact.UTF8String;
  keyset * k;
  int nk = all_keys (contact, &k);
  uint64_t latest_time = 0;
  for (int ik = 0; ik < nk; ik++) {
    uint64_t seq;
    uint64_t time = 0;
    int tz_min;
    char ack [MESSAGE_ID_SIZE];
    int mtype = highest_seq_record(contact, k [ik], msgType, &seq, &time, &tz_min, NULL, ack, NULL, NULL);
    // NSLog(@"mtype for contact %s/%d is %d (%d), time %ld\n", contact, k[ik], mtype, MSG_TYPE_DONE, (long) time);
    if ((mtype != MSG_TYPE_DONE) && (time > latest_time))
      latest_time = time;
  }
  if (nk > 0)
    free (k);
  return (NSInteger)latest_time;
}

- (NSString *)lastReceived:(NSString *) contact {
  uint64_t latest_time_received = lastTime(contact, MSG_TYPE_RCVD);
  if (latest_time_received == 0)
    return nil;
  // objective C time begins on January 1st, 2001.  allnet time begins on January 1st, 2000.
  uint64_t unixTime = latest_time_received + ALLNET_Y2K_SECONDS_IN_UNIX;
  NSDate * date = [[NSDate alloc] initWithTimeIntervalSince1970:unixTime];
  // date formatter code from https://developer.apple.com/library/ios/documentation/Cocoa/Conceptual/DataFormatting/Articles/dfDateFormatting10_4.html#//apple_ref/doc/uid/TP40002369-SW1
  NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
  [dateFormatter setDateStyle:NSDateFormatterMediumStyle];
  [dateFormatter setTimeStyle:NSDateFormatterMediumStyle];
  NSString * result = [dateFormatter stringFromDate:date];
  //NSLog(@"date for contact %@ is %@\n", contact, result);
  return result;
}

- (NSString *)latestContact {
  NSString * result = nil;
  NSInteger latest = 0;
  //NSLog(@"self.contacts is %@\n", self.contacts);
  if (self.contacts != nil) {
    for (NSObject * item in self.contacts) {
      //NSLog(@"item is %@\n", [item class]);
      if ([item isKindOfClass:[NSString class]]) {
        NSString * contact = (NSString *)item;
        NSInteger latestForThisContact = lastTime(contact, MSG_TYPE_ANY);
        //NSLog(@"looking at %@, %d\n", contact, latestForThisContact);
        if ((result == nil) || (latest < latestForThisContact)) {
          result = contact;
          latest = latestForThisContact;
        }
      }
    }
  }
  return result;
}

- (void)didReceiveMemoryWarning {
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
  NSLog(@"ContactsUITableViewController received memory warning\n");
}

#pragma mark - Table view data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
  // Return the number of sections.
  return 1;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
  // Return the number of rows in the section.
  int contactsCount = (int)[self.contacts count];
  int hiddenCount = invisible_contacts (NULL);
  if (self.displaySettings)
    contactsCount += hiddenCount;
  int settingsButtonCount = 0;   // 0 or 1, but arithmetic, not boolean
  if (self.displaySettings || (contactsCount > 0) || (hiddenCount > 0))
    settingsButtonCount = 1;
  return contactsCount + NUM_HEADER_ROWS + settingsButtonCount;
}

- (void)contactButtonClicked:(id) source {
  UIButton * button = (UIButton *) source;
  // NSLog(@"in contactButtonClicked, source %@, tag %d\n", source, (int)button.tag);
  NSString * contact = nil;
  contact = [self.contacts objectAtIndex:button.tag];
  NSLog(@"in contactButtonClicked, text %@, contact %@\n", button.currentTitle, contact);
  if (self.contactName != nil) {
    self.contactName.text = contact;
    [self displayingContact:contact];
    if (self.conversation != nil) {
      [self.conversation displayContact:contact];
      self.tabBarController.selectedIndex = 1;
    }
  }
  // NSLog(@"\n\n in contactButtonClicked, tab bar is %@, item %@, view %@\n\n", self.tabBarController, self.tabBarItem, self.tableView);
}

- (void)editButtonClicked:(id) source {
  UIButton * button = (UIButton *) source;
  NSLog(@"in editButtonClicked, source %@, tag %d\n", source, (int)button.tag);
  NSString * contact = nil;
  if (button.tag < [self.contacts count])
    contact = [self.contacts objectAtIndex:button.tag];
  else if (button.tag < ([self.contacts count] + [self.hiddenContacts count]))
    contact = [self.hiddenContacts objectAtIndex:(button.tag - [self.contacts count])];
  else
    NSLog(@"error in ButtonClicked, tag %d, lengths %d %d, ignoring\n", (int)button.tag, (int)[self.contacts count], (int)[self.hiddenContacts count]);
  NSLog(@"in editButtonClicked, text %@, contact %@\n", button.currentTitle, contact);
  SettingsViewController * next = nil;
  if (next == nil)
    next = [self.storyboard instantiateViewControllerWithIdentifier:@"SettingsViewController"];
  if ((contact != nil) && (next != nil)) {
    [next initialize:strcpy_malloc (contact.UTF8String, "editButtonClicked")];
    [self presentViewController:next animated:NO completion:nil];
    self.contactName.text = contact;
    [self displayingContact:contact];
  }
  // NSLog(@"\n\n in contactButtonClicked, tab bar is %@, item %@, view %@\n\n", self.tabBarController, self.tabBarItem, self.tableView);
}

- (void)settingsButtonClicked:(id) source {
  self.displaySettings = ! self.displaySettings;
  [self.tableView reloadData];
  NSLog(@"settings button clicked, %d\n", self.displaySettings);
}

/*
 - (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
 UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:<#@"reuseIdentifier"#> forIndexPath:indexPath];
 
 // Configure the cell...
 
 return cell;
 }
 */
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
  UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"ListPrototypeCell" forIndexPath:indexPath];
  // remove any earlier content from this cell
  cell.backgroundColor = UIColor.whiteColor;
  cell.textLabel.text = @"";
  for (NSObject *item in [cell.contentView subviews]) {
    if ([item isMemberOfClass:[UIButton class]]) {
      UIButton * button = (UIButton *) item;
      [button removeFromSuperview];
    }
  }
  
  if (cell == nil)
    NSLog(@"cell is nil\n");
  NSLog(@"got cell %@\n", cell);
  int row = (int)indexPath.row;
  // Configure the cell:
  int numVisibleContacts = (int)[self.contacts count];
  int numContacts = numVisibleContacts;
  if (self.displaySettings)
    numContacts += [self.hiddenContacts count];
  if (row < NUM_HEADER_ROWS) {
    if (row == 1) {
      cell.textLabel.text = [self contactHeaderString:self.contactsWithNewMessages.count :YES];
      cell.backgroundColor = UIColor.yellowColor;
    } else if (row == 2) {
      cell.textLabel.text = [self contactHeaderString:self.contacts.count :NO];
      cell.backgroundColor = UIColor.yellowColor;
    } else {
      cell.textLabel.text = @"";
    }
  } else if (row - NUM_HEADER_ROWS < numContacts) {
    int index = row - NUM_HEADER_ROWS;
    NSString * value = nil;
    BOOL visible = (index < numVisibleContacts);
    if (visible)
      value = [self.contacts objectAtIndex:index];
    else
      value = [self.hiddenContacts objectAtIndex:(index - numVisibleContacts)];
    UIButton * button = [UIButton buttonWithType: UIButtonTypeSystem];
    NSString * title = value;
    if (visible && (! self.displaySettings)) {
      NSString * timeString = [self lastReceived:value];
      NSNumber * count = [self.contactsWithNewMessages objectForKey:value];
      if (count != nil) {
        if (count.integerValue != 1)
          title = [value stringByAppendingFormat:@" -- %@ new messages", count];
        else
          title = [value stringByAppendingFormat:@" -- 1 new message"];
        button.backgroundColor = UIColor.greenColor;
      } else if (timeString != nil) {
        title = [value stringByAppendingString:@" -- "];
        title = [title stringByAppendingString:timeString];
      }
    } else if (! visible) {
      title = [value stringByAppendingString:@" (not visible)"];
    }
    // NSLog(@"on row %d creating button with title %@\n", row, title);
    // left align title
    button.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    button.contentEdgeInsets = UIEdgeInsetsMake(0, 10, 0, 0);
    // [button setTitle:title forState:UIControlStateNormal];
    NSMutableAttributedString * titleWithFont = [[NSMutableAttributedString alloc]
                                                 initWithString:title];
    UIFont * preferredFont = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    [titleWithFont addAttribute:NSFontAttributeName
                          value:preferredFont
                          range:NSMakeRange(0, titleWithFont.length)];
    // CGFloat preferredFontHeight = preferredFont.lineHeight;
    [button setAttributedTitle:titleWithFont forState:UIControlStateNormal];
    // need a frame, otherwise nothing to click
    button.frame = CGRectMake(0.0, 0.0, 9999.0, 40.0);
    // use the tag as an index into contacts
    [button setTag:row - NUM_HEADER_ROWS];
    if (! self.displaySettings) {
      [button addTarget:self action:@selector(contactButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
    } else {
      [button addTarget:self action:@selector(editButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
      [button setTintColor:UIColor.greenColor];
    }
    // add the button
    [cell.contentView addSubview:button];
    // NSLog(@"set cell content subview to %@.%d (%@)\n", button, (int)button.tag, button.titleLabel.text);
  } else {   // settings button
    UIButton * button = [UIButton buttonWithType: UIButtonTypeSystem];
    NSString * title = @"edit contacts";
    if (self.displaySettings)
      title = @"return to contacts list";
    button.backgroundColor = UIColor.yellowColor;
    // left align title
    button.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    button.contentEdgeInsets = UIEdgeInsetsMake(0, 10, 0, 0);
    // [button setTitle:title forState:UIControlStateNormal];
    NSMutableAttributedString * titleWithFont = [[NSMutableAttributedString alloc]
                                                 initWithString:title];
    UIFont * preferredFont = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    [titleWithFont addAttribute:NSFontAttributeName
                          value:preferredFont
                          range:NSMakeRange(0, titleWithFont.length)];
    // CGFloat preferredFontHeight = preferredFont.lineHeight;
    [button setAttributedTitle:titleWithFont forState:UIControlStateNormal];
    // need a frame, otherwise nothing to click
    button.frame = CGRectMake(0.0, 0.0, 9999.0, 40.0);
    // use the tag as an index into contacts
    [button setTag:row - NUM_HEADER_ROWS];
    [button addTarget:self action:@selector(settingsButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
    // remove any earlier buttons, and add this one
    for (NSObject *item in [cell.contentView subviews]) {
      if ([item isMemberOfClass:[UIButton class]]) {
        UIButton * earlierButton = (UIButton *) item;
        [earlierButton removeFromSuperview];
      }
    }
    [cell.contentView addSubview:button];
  }
  return cell;
}

// if n is 0, sets to zero.  Otherwise, adds n (positive or negative) to the current badge number
- (void) addToBadgeNumber: (NSInteger) n {
  UIApplication * app = [UIApplication sharedApplication];
  if (n == 0) {
    app.applicationIconBadgeNumber = 0;
  } else {
    app.applicationIconBadgeNumber = app.applicationIconBadgeNumber + n;
  }
  NSLog(@"icon badge number is now %ld\n", (long)app.applicationIconBadgeNumber);
}

- (void) displayingContact: (NSString *) contact {
  if ([self.contactsWithNewMessages objectForKey:contact] != nil) {
    NSNumber * count = [self.contactsWithNewMessages objectForKey:contact];
    if (count.integerValue > 0) {
      [self addToBadgeNumber: (- (int)count.integerValue)];
    }
    [self.contactsWithNewMessages removeObjectForKey:contact];
    [self.tableView reloadData];
  }
}

// is the conversation being displayed or hidden?
- (void) notifyConversationChange: (BOOL) beingDisplayed {
  // to do: debug why the new message is not displayed if it is delivered while we are in the background
  self.conversationIsDisplayed = beingDisplayed;
  // if displayed, remove any notifications for the contact being displayed
  if ((beingDisplayed) && (self.conversation != nil) && ([self.conversation selectedContact] != nil)) {
    [self displayingContact:[self.conversation selectedContact]];
    // display any new messages
    [self.conversation displayContact:[self.conversation selectedContact]];
  }
}

// when the interface is displayed, note that this contact has a new message
- (void) newMessage: (NSString *) contact {
  // selectedContact may be nil, contact should not be nil, so use [contact isEqual:]
  BOOL sameAsConversation = ([contact isEqual:[self.conversation selectedContact]]);
  BOOL contactIsDisplayed = (self.conversationIsDisplayed && sameAsConversation);
  NSLog(@"new message for contact %@, displayed %d %d\n", contact, sameAsConversation, contactIsDisplayed);
  AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
  if ((! contactIsDisplayed) || (! [appDelegate appIsInForeground])) {   // add the notification
    NSNumber * previous = [self.contactsWithNewMessages objectForKey:contact];
    NSNumber * next = nil;
    if (previous == nil)
      next = [[NSNumber alloc] initWithInt: 1];
    else
      next = [[NSNumber alloc] initWithInt:((int)previous.integerValue + 1)];
    [self.contactsWithNewMessages setObject:next forKey:contact];
    [self setContacts];   // refresh the contacts list
    [self.tableView reloadData];
    [self addToBadgeNumber:1];
  } else {  // this contact is already displayed, update the contents
    [self.conversation displayContact: contact];
  }
  //NSLog(@"%d contacts with new messages, %@\n", self.contactsWithNewMessages.count, self.contacts);
}

/*
 // Override to support conditional editing of the table view.
 - (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
 // Return NO if you do not want the specified item to be editable.
 return YES;
 }
 */

/*
 // Override to support editing the table view.
 - (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath *)indexPath {
 if (editingStyle == UITableViewCellEditingStyleDelete) {
 // Delete the row from the data source
 [tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationFade];
 } else if (editingStyle == UITableViewCellEditingStyleInsert) {
 // Create a new instance of the appropriate class, insert it into the array, and add a new row to the table view
 }
 }
 */

/*
 // Override to support rearranging the table view.
 - (void)tableView:(UITableView *)tableView moveRowAtIndexPath:(NSIndexPath *)fromIndexPath toIndexPath:(NSIndexPath *)toIndexPath {
 }
 */

/*
 // Override to support conditional rearranging of the table view.
 - (BOOL)tableView:(UITableView *)tableView canMoveRowAtIndexPath:(NSIndexPath *)indexPath {
 // Return NO if you do not want the item to be re-orderable.
 return YES;
 }
 */

#pragma mark - Navigation
/*
 // In a storyboard-based application, you will often want to do a little preparation before navigation
 - (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
 // Get the new view controller using [segue destinationViewController].
 // Pass the selected object to the new view controller.
 NSLog(@"ContactsUITableViewController prepareForSegue (%@ %@ %@)\n", segue, [segue destinationViewController], sender);
 }
 */
@end
