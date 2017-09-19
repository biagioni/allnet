//
//  SettingsViewController.m
//  allnet-xchat
//
//  Created by e on 2016/07/05.
//  Copyright © 2016 allnet. All rights reserved.
//

#import "SettingsViewController.h"

#include "lib/util.h"
#include "lib/keys.h"
#include "xchat/store.h"

@interface SettingsViewController ()

@property UIButton * doneButton;
@property UIButton * cancelButton;
@property UISwitch * visibleSwitch;
@property UISwitch * notifySwitch;
@property UISwitch * saveConversationSwitch;
@property UIButton * exportConversationButton;
@property UIButton * toPasteboardConversationButton;  // xcode doesn't like the name copyConversationButton
@property UIButton * deleteConversationButton;
@property UIButton * deleteContactButton;
@property UITextField * renameTextField;
@property NSInteger addToGroup;
@property NSInteger deleteFromGroup;
@property NSMutableArray * addGroups;
@property NSMutableArray * deleteGroups;
@property UISegmentedControl * addSegment;
@property UISegmentedControl * deleteSegment;

@property BOOL deletingConversation;
@property BOOL deletingContact;

#define EXPORT_CONVERSATION_TO_FILE           1
#define EXPORT_CONVERSATION_TO_PASTEBOARD     2
@property int exportingConversation;  // 0 if not exporting, otherwise one of the values above, or the OR of both

@property UIColor * savedButtonColor;

@end

#define TAG_DONE                1
#define TAG_CANCEL              2
#define TAG_DELETE_FROM_GROUP   3
#define TAG_ADD_TO_GROUP        4
#define TAG_VISIBLE             5
#define TAG_DELETE_CONVERSATION 6
#define TAG_DELETE_CONTACT      7
#define TAG_RENAME_TEXT         8
#define TAG_EXPORT_CONVERSATION 9
#define TAG_REMOVE_FROM_GROUP_SELECTOR  10
#define TAG_ADD_TO_GROUP_SELECTOR       11
#define TAG_NOTIFY_SWITCH       12
#define TAG_SAVE_CONVERSATION   13
#define TAG_COPY_CONVERSATION   14

@implementation SettingsViewController

- (void)initialize: (const char *)contact {
  self.contact = contact;
  self.doneButton = nil;
  self.cancelButton = nil;
  self.visibleSwitch = nil;
  self.notifySwitch = nil;
  self.saveConversationSwitch = nil;
  self.deleteConversationButton = nil;
  self.deleteContactButton = nil;
  self.deletingContact = NO;
  self.deletingConversation = NO;
  self.exportingConversation = 0;
  self.renameTextField = nil;
  self.savedButtonColor = nil;
  self.addToGroup = -1;
  self.deleteFromGroup = -1;
  self.addGroups = [[NSMutableArray alloc] init];
  self.deleteGroups = [[NSMutableArray alloc] init];
  self.addSegment = nil;
  self.deleteSegment = nil;
  // compute the size of this contact's conversation, to set the label on the "delete conversation" button
  NSString * newDeleteConversationButtonLabel = nil;
  int64_t sizeInBytes = conversation_size (contact);
  int64_t sizeInMegabytes = sizeInBytes / (1000 * 1000);
  char sizeBuf [100];
  if (sizeInMegabytes >= 10)
    snprintf (sizeBuf, sizeof (sizeBuf), "%" PRId64 "", sizeInMegabytes);
  else
    snprintf (sizeBuf, sizeof (sizeBuf), "%" PRId64 ".%02" PRId64 "", sizeInMegabytes, (sizeInBytes / 10000) % 100);
  NSString * actualSize = [[NSString alloc] initWithUTF8String:sizeBuf];
  // initialize the various buttons
  BOOL isGroup = ((contact != NULL) && (is_group (contact)));
  BOOL isInGroup = ((contact != NULL) && (member_of_groups(contact, NULL) > 0));
  NSLog(@"contact %s is a member of %d groups (%d)\n", contact, member_of_groups(contact, NULL), isInGroup);
  NSArray * subviews = self.view.subviews;
  for (NSObject * item in subviews) {  // create self.message first, used in self.conversation initialize
    if ([item isMemberOfClass: [UIButton class]]) {
      UIButton * button = (UIButton *) item;
      switch (button.tag) {
        case TAG_DONE:
          self.doneButton = button;
          break;
        case TAG_CANCEL:
          self.cancelButton = button;
          break;
        case TAG_EXPORT_CONVERSATION:
          [button addTarget:self action:@selector(exportConversationButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
          self.exportConversationButton = button;
          break;
        case TAG_COPY_CONVERSATION:
          [button addTarget:self action:@selector(copyConversationButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
          self.toPasteboardConversationButton = button;
          break;
        case TAG_DELETE_CONVERSATION:
          newDeleteConversationButtonLabel = [button.titleLabel.text stringByReplacingOccurrencesOfString:@"1" withString:actualSize];
          [button setTitle:newDeleteConversationButtonLabel forState:UIControlStateNormal];
          [button addTarget:self action:@selector(deleteConversationButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
          self.deleteConversationButton = button;
          self.savedButtonColor = button.currentTitleColor;
          break;
        case TAG_DELETE_CONTACT:
          [button addTarget:self action:@selector(deleteContactButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
          self.deleteContactButton = button;
          break;
        default:
          NSLog(@"settings found button with unknown tag %d, label %@, button %@\n", (int)button.tag, button.titleLabel, button);
          break;
      }
    } else if ([item isMemberOfClass:[UISegmentedControl class]]) {
      UISegmentedControl * seg = (UISegmentedControl *) item;
      NSLog(@"configuring segment %@, remove %d\n", seg, seg.tag == TAG_REMOVE_FROM_GROUP_SELECTOR);
      [self configureSegmented:seg:contact];
    } else if ([item isMemberOfClass:[UISwitch class]]) {
      UISwitch * sw = (UISwitch *) item;
      switch (sw.tag) {
        case TAG_VISIBLE:
          self.visibleSwitch = sw;
          if (is_invisible(contact))
            self.visibleSwitch.on = NO;
          if (self.visibleSwitch.on) {
            [self.deleteContactButton setEnabled:NO];
          } else {
            self.notifySwitch.on = FALSE;
            [self.deleteContactButton setEnabled:YES];
          }
          [sw addTarget:self action:@selector(visibleSwitchChanged:) forControlEvents:UIControlEventValueChanged];
          break;
        case TAG_NOTIFY_SWITCH:
          self.notifySwitch = sw;
          // [sw addTarget:self action:@selector(notifySwitchChanged:) forControlEvents:UIControlEventValueChanged];
          break;
        case TAG_SAVE_CONVERSATION:
          self.saveConversationSwitch = sw;
          // [sw addTarget:self action:@selector(saveSwitchChanged:) forControlEvents:UIControlEventValueChanged];
          if (isGroup)
            [sw setHidden:YES];  // don't allow groups to save conversations
          break;
        default:
          NSLog(@"settings found switch with unknown tag %d, switch %@\n", (int)sw.tag, sw);
          break;
      }
      NSLog(@"settings found switch with tag %d, switch %@\n", (int)sw.tag, sw);
    } else if ([item isMemberOfClass:[UITextField class]]) {
      UITextField * rename = (UITextField *) item;
      if (rename.tag == TAG_RENAME_TEXT) {
        [rename setText:[[NSString alloc] initWithUTF8String:contact]];
        self.renameTextField = rename;
      }
    } else if ([item isMemberOfClass:[UILabel class]]) {
      UILabel * label = (UILabel *) item;
      if (label.tag == TAG_SAVE_CONVERSATION) {
        if (isGroup)
          [label setHidden:YES];
      } else if (label.tag == TAG_DELETE_FROM_GROUP)
        [label setHidden:(! [self showDeleteGroup:contact])];
      else if (label.tag == TAG_ADD_TO_GROUP)
        [label setHidden:(! [self showAddGroup:contact])];
    }
  }
  NSLog(@"in initialize, settings buttons: %@ %@ %@ %@, switches %@ %@ %@, contact %s\n", self.doneButton.titleLabel.text, self.cancelButton.titleLabel.text, self.deleteConversationButton.titleLabel.text, self.deleteContactButton.titleLabel.text, self.visibleSwitch, self.notifySwitch, self.saveConversationSwitch, self.contact);
  if (self.doneButton != nil)
    NSLog(@"done button label is %@\n", self.doneButton.titleLabel);
}

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view.
  // NSLog(@"SettingsViewController.m: viewDidLoad\n");
}

- (void)didReceiveMemoryWarning {
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

- (BOOL)showAddGroup: (const char *) contact {
  int nmember = member_of_groups(contact, NULL);
  int ngroups = all_groups (NULL);
  if (is_group (contact))
    ngroups--;  // don't count this group;
  NSLog(@"%s is member of %d groups, out of %d total\n", contact, nmember, ngroups);
  return nmember < ngroups;
}

- (BOOL)showDeleteGroup: (const char *) contact {
  NSLog(@"%s is member of %d groups (for showDeleteGroup)\n", contact, member_of_groups(contact, NULL));
  return member_of_groups(contact, NULL) > 0;
}

- (void)configureSegmented: (UISegmentedControl *)seg :(const char *)contact {
  if (contact == NULL)
    return;
  // BOOL isGroup = (is_group (contact));
  // BOOL isInGroup = (member_of_groups(contact, NULL) > 0);
  BOOL removeSelector = (seg.tag == TAG_REMOVE_FROM_GROUP_SELECTOR);
  //if (isGroup || (removeSelector && (! isInGroup))) {
  //[seg setHidden:YES];
  // } else {
  if (removeSelector) {
    char ** groups = NULL;
    int n = member_of_groups(contact, &groups);
    if ((n <= 0) || (groups == NULL) || (! [self showDeleteGroup:contact])) {
      [seg setHidden:YES];
      return;
    }
    [seg removeAllSegments];
    for (int i = 0; i < n; i++) {
      if (strcasecmp(contact, groups [i]) != 0) {
        NSString * title = [[NSString alloc] initWithUTF8String:groups [i]];
        [seg insertSegmentWithTitle:title atIndex:0 animated:NO];
        [self.deleteGroups insertObject:title atIndex:0];
      }
    }
    free (groups);
    [seg addTarget:self action:@selector(removeFromGroupSegmentButtonClicked:) forControlEvents:UIControlEventValueChanged];
    self.deleteSegment = seg;
  } else {  // add selector: list groups to which we can be added
    char ** groups = NULL;
    int n = all_groups (&groups);
    if ((n <= member_of_groups(contact, NULL)) || (! [self showAddGroup:contact])) {
      [seg setHidden:YES];
    } else {
      char ** already_member = NULL;
      int nmember = member_of_groups(contact, &already_member);
      [seg removeAllSegments];
      for (int i = 0; i < n; i++) {
        if ((! is_in_string_list (groups [i], already_member, nmember)) &&
            (strcasecmp(contact, groups [i]) != 0)) {
          NSString * title = [[NSString alloc] initWithUTF8String:groups [i]];
          [seg insertSegmentWithTitle:title atIndex:0 animated:NO];
          [self.addGroups insertObject:title atIndex:0];
        }
      }
      [seg addTarget:self action:@selector(addToGroupSegmentButtonClicked:) forControlEvents:UIControlEventValueChanged];
      if (already_member != NULL)
        free (already_member);
    }
    if (groups != NULL)
      free (groups);
    self.addSegment = seg;
  }
  // }
  [seg setNeedsLayout];
  [seg setNeedsDisplay];
  NSLog(@"initially, selected segment index is %ld, add group %@, delete group %@\n", (long)seg.selectedSegmentIndex, self.addGroups, self.deleteGroups);
}

static int all_groups (char *** groups)
{
  if (groups != NULL)
    *groups = NULL;
  char ** contacts = NULL;
  int n = all_contacts (&contacts);
  if ((n <= 0) || (contacts == NULL)) {
    if (contacts != NULL)
      free (contacts);
    return 0;
  }
  int ngroups = 0;
  for (int i = 0; i < n; i++) {
    if (is_group (contacts [i]))
      ngroups++;
  }
  if ((ngroups > 0) && (groups != NULL)) {
    int group_index = 0;
    for (int i = 0; i < n; i++) {
      if (is_group (contacts [i])) {
        if (group_index < i)
          contacts [group_index] = contacts [i];
        group_index++;
      }
    }
    *groups = contacts;  // copied contacts that are groups into the first 0..ngroups-1 positions in contacts
  } else {
    free (contacts);
  }
  return ngroups;
}

static int is_in_string_list (const char * needle, char ** haystack, int nhay)
{
  for (int i = 0; i < nhay; i++)
    if (strcmp (needle, haystack [i]) == 0)
      return 1;
  return 0;
}

#pragma mark - Navigation

// if both are set, the conversation is exported before being deleted
void confirm_changes (const char * contact, const char * new_name, int visible, int notify, int save_messages, int conversation_delete, int contact_delete)
{
  NSLog(@"done button pressed, for contact %s: visible %d, delete conversation %d, contact %d\n",
        contact, visible, conversation_delete, contact_delete);
  NSLog(@"warning: do something with notify %d and save_messages %d\n", notify, save_messages);
  if (visible != (is_visible (contact))) {
    if (visible) {  // make visible
      if (! make_visible(contact))
        NSLog(@"unable to unhide %s\n", contact);
    } else {
      if (! make_invisible(contact))
        NSLog(@"unable to hide %s\n", contact);
    }
  }
  if ((new_name != NULL) && (strcmp (new_name, "") != 0) && (strcmp (contact, new_name) != 0)) {
    NSLog(@"renaming contact from '%s' to '%s'\n", contact, new_name);
    if (rename_contact (contact, new_name)) {
      NSLog(@"rename_contact successful\n");
    } else {
      NSLog(@"rename_contact failed\n");
    }
  }
  if (contact_delete || conversation_delete)
    delete_conversation (contact);
  if (contact_delete) {
    delete_contact (contact);
    return;
  }
}

void undo_changes ()
{
  NSLog(@"cancel button pressed\n");
}

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
  // Get the new view controller using [segue destinationViewController].
  // Pass the selected object to the new view controller.
  NSLog (@"settings preparing for segue to %@, sender %@, contact %s\n", [segue destinationViewController], sender, self.contact);
  if ([sender isMemberOfClass:[UIButton class]]) {
    UIButton * button = (UIButton *) sender;
    if (button.tag == TAG_DONE) {
      if (self.exportingConversation != 0)  // do it before any deletion
        [self export_conversation:[[NSString alloc] initWithUTF8String:self.contact] selector:self.exportingConversation];
      if ((self.addToGroup >= 0) && (self.addGroups != nil) &&
          (self.addToGroup < self.addGroups.count)) {
        NSString * group = (NSString *)self.addGroups [self.addToGroup];
        NSLog(@"adding contact %s to group %s gives %d\n",self.contact, group.UTF8String,
              add_to_group(group.UTF8String, self.contact));
        [self configureSegmented:self.addSegment :self.contact];
      }
      NSLog(@"deleting %lu from %lu groups\n", (long)self.deleteFromGroup, (unsigned long)self.deleteGroups.count);
      if ((self.deleteFromGroup >= 0) && (self.deleteGroups != nil) &&
          (self.deleteFromGroup < self.deleteGroups.count)) {
        NSString * group = (NSString *)self.deleteGroups [self.deleteFromGroup];
        NSLog(@"removing contact %s from group %s gives %d\n", self.contact, group.UTF8String,remove_from_group(group.UTF8String, self.contact));
        [self configureSegmented:self.deleteSegment :self.contact];
      }
      confirm_changes (self.contact, self.renameTextField.text.UTF8String, self.visibleSwitch.on, self.notifySwitch.on, self.saveConversationSwitch.on, self.deletingConversation, self.deletingContact);
    } else if (button.tag == TAG_CANCEL) {
      undo_changes ();
    } else {
      NSLog(@"settings unknown segue 1 to %@, sender %@\n", [segue destinationViewController], sender);
    }
  } else
    NSLog(@"settings unknown segue 2 to %@, sender %@\n", [segue destinationViewController], sender);
  // [self.tabBarController setSelectedIndex:2]; // doesn't do anything
  self.tabBarController.selectedIndex = 2;  // doesn't seem to do anything
}

- (IBAction)exportConversationButtonClicked:(id)sender {
  NSLog(@"exportConversation button clicked, sender %@, contact %s\n", sender, self.contact);
  if ((self.exportingConversation & EXPORT_CONVERSATION_TO_FILE) != 0) {
    self.exportingConversation &= (~ EXPORT_CONVERSATION_TO_FILE);
    [self resetButton:self.exportConversationButton];
  } else {
    self.exportingConversation |= EXPORT_CONVERSATION_TO_FILE;
    NSLog(@"setting button selected\n");
    [self setButtonSelected:self.exportConversationButton warning:NO];
  }
}

- (IBAction)copyConversationButtonClicked:(id)sender {
  NSLog(@"copyConversation button clicked, sender %@, contact %s, value %d\n", sender, self.contact, self.exportingConversation);
  if ((self.exportingConversation & EXPORT_CONVERSATION_TO_PASTEBOARD) != 0) {
    self.exportingConversation &= (~ EXPORT_CONVERSATION_TO_PASTEBOARD);
    [self resetButton:self.toPasteboardConversationButton];
  } else {
    self.exportingConversation |= EXPORT_CONVERSATION_TO_PASTEBOARD;
    NSLog(@"setting button selected %d\n", self.exportingConversation);
    [self setButtonSelected:self.toPasteboardConversationButton warning:NO];
  }
}

- (void)resetButton: (UIButton *) button {
  NSString * current = [button currentTitle];
  if (current != nil) {
    NSArray<NSString *> * parts = [current componentsSeparatedByString:@" ("];
    if ([parts count] > 1)  // selected, reset title
      [button setTitle:parts [0] forState:UIControlStateNormal];
  }
  if (self.savedButtonColor != nil)
    [button setTitleColor:self.savedButtonColor forState:UIControlStateNormal];
  else
    [button setTitleColor:[UIColor blueColor] forState:UIControlStateNormal];
}

- (void)resetDeleteButtons {
  [self resetButton:self.deleteConversationButton];
  [self resetButton:self.deleteContactButton];
}

- (void)setButtonSelected:(UIButton *) button warning:(BOOL)makeRed {
  NSLog(@"original button color is %@ for button %@, saved color %@\n", button.currentTitleColor, button, self.savedButtonColor);
  [button setTitle:[button.currentTitle stringByAppendingString:@" (selected)"] forState:UIControlStateNormal];
  if (makeRed)
    [button setTitleColor:[UIColor redColor] forState: UIControlStateNormal];
}

- (IBAction)deleteConversationButtonClicked:(id)sender {
  NSLog(@"deleteConversation button clicked, sender %@, %d %d\n", sender, self.deletingConversation, self.deletingContact);
  if (self.deletingConversation) {
    self.deletingConversation = NO;
    self.deletingContact = NO;
    [self resetDeleteButtons];
  } else {
    self.deletingConversation = YES;
    [self setButtonSelected:self.deleteConversationButton warning:YES];
  }
  NSLog(@"at end of deleteConversation %d %d\n", self.deletingConversation, self.deletingContact);
}

- (IBAction)deleteContactButtonClicked:(id)sender {
  NSLog(@"deleteContact button clicked, sender %@, %d %d\n", sender, self.deletingConversation, self.deletingContact);
  if (self.deletingContact) {
    self.deletingContact = NO;
    self.deletingConversation = NO;
    [self resetDeleteButtons];
  } else {
    self.deletingContact = YES;
    [self setButtonSelected:self.deleteContactButton warning:YES];
    [self.deleteContactButton setTitleColor:[UIColor redColor] forState: UIControlStateNormal];
    if (! self.deletingConversation)
      [self setButtonSelected:self.deleteConversationButton warning:YES];
  }
  NSLog(@"at end of deleteContact %d %d\n", self.deletingConversation, self.deletingContact);
}

- (IBAction)visibleSwitchChanged:(id)sender {
  NSLog(@"visibleSwitch changed, sender %@, switch is %d\n", sender, self.visibleSwitch.on);
  if (self.visibleSwitch.on) {
    [self.deleteContactButton setEnabled:NO];
  } else {
    self.notifySwitch.on = FALSE;
    [self.deleteContactButton setEnabled:YES];
  }
  NSLog(@"at end of visibleSwitchButtonClicked\n");
}

- (IBAction)addToGroupSegmentButtonClicked:(id)sender {
  if ([sender isMemberOfClass: [UISegmentedControl class]]) {
    UISegmentedControl * seg = (UISegmentedControl *) sender;
    NSLog(@"selected segment index is %ld, add group %@\n", (long)seg.selectedSegmentIndex, self.addGroups [seg.selectedSegmentIndex]);
    self.addToGroup = seg.selectedSegmentIndex;
  }
  NSLog(@"addToGroupSegment button clicked, sender %@\n", sender);
}

- (IBAction)removeFromGroupSegmentButtonClicked:(id)sender {
  if ([sender isMemberOfClass: [UISegmentedControl class]]) {
    UISegmentedControl * seg = (UISegmentedControl *) sender;
    NSLog(@"selected segment index is %ld, delete group %@\n", (long)seg.selectedSegmentIndex, self.deleteGroups [seg.selectedSegmentIndex]);
    self.deleteFromGroup = seg.selectedSegmentIndex;
  }
  NSLog(@"removeFromGroupSegment button clicked, sender %@\n", sender);
}

- (void) export_conversation:(NSString *)contact selector: (int) sel
{
  const char * cp = contact.UTF8String;
  NSLog(@"exporting conversation for %@, selector %d\n", contact, sel);
  if (is_group(cp)) {
    NSLog(@"unable to export conversation for group\n");
    return;
  }
  NSMutableString * result = [[NSMutableString alloc] initWithString:@""];
  struct message_store_info * msgs = NULL;
  int num_used = 0;
  int num_alloc = 0;
  if (list_all_messages(cp, &msgs, &num_alloc, &num_used)) {
    for (int i = 0; i < num_used; i++) {
      NSString * typeString = @"unknown message type";
      NSString * seqString = @"unknown sequence";
      NSString * timeString = @"unknown time";
      NSString * rcvdTimeString = @"";
      NSString * sizeString = @"unknown size";
      char timeBuf [ALLNET_TIME_STRING_SIZE];
      if (msgs [i].msg_type == MSG_TYPE_SENT) {
        typeString = @"sent";
        if (msgs [i].message_has_been_acked)
          seqString = [[NSString alloc] initWithFormat:@"sequence %" PRIu64 " (acked)", msgs [i].seq];
        else
          seqString = [[NSString alloc] initWithFormat:@"sequence number %" PRIu64 "", msgs [i].seq];
        allnet_localtime_string (msgs [i].time, timeBuf);
        timeString = [[NSString alloc] initWithFormat:@"sent at %s", timeBuf];
        sizeString = [[NSString alloc] initWithFormat:@"%zd bytes", msgs [i].msize];
      } else if (msgs [i].msg_type == MSG_TYPE_RCVD) {
        typeString = @"received";
        seqString = [[NSString alloc] initWithFormat:@"sequence number %" PRIu64 "", msgs [i].seq];
        allnet_localtime_string (msgs [i].time, timeBuf);
        timeString = [[NSString alloc] initWithFormat:@"sent at %s", timeBuf];
        allnet_localtime_string (msgs [i].rcvd_time, timeBuf);
        rcvdTimeString = [[NSString alloc] initWithFormat:@"received at %s ", timeBuf];
        sizeString = [[NSString alloc] initWithFormat:@"%zd bytes", msgs [i].msize];
      } else {
        NSLog (@"export_conversation: unexpected message type %d\n", msgs [i].msg_type);
      }
      NSString * line = [[NSString alloc] initWithFormat:@"%@ %@ %@ %@%@: %s\n", typeString, seqString, timeString, rcvdTimeString, sizeString, msgs [i].message];
      [result insertString:line atIndex:0];
    }
    free_all_messages(msgs, num_used);
    //NSLog (@"exported conversation is\n%@\n", result);
    if ((sel | EXPORT_CONVERSATION_TO_PASTEBOARD) != 0) {
      UIPasteboard * generalPasteboard = [UIPasteboard generalPasteboard];
      //[generalPasteboard setValue:result forPasteboardType:@"public.plain-text"];
      [generalPasteboard setString:result];
      NSLog(@"saved to pasteboard\n");
    }
    if ((sel | EXPORT_CONVERSATION_TO_FILE) != 0) {
      // adapted from http://stackoverflow.com/questions/5619719/write-a-file-on-ios#5619855
      time_t now = time (NULL);
      struct tm tm;
      localtime_r (&now, &tm);
      //get the documents directory:
      NSArray * paths = NSSearchPathForDirectoriesInDomains (NSDocumentDirectory, NSUserDomainMask, YES);
      NSString * documentsDirectory = [paths objectAtIndex:0];
      //make a file name to write the data to using the documents directory:
      NSString * destination = [NSString stringWithFormat:@"%@/%@-%04d%02d%02d-%02d%02d%02d.txt",
                                documentsDirectory, contact,
                                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                                tm.tm_hour, tm.tm_min, tm.tm_sec];
      NSLog (@"saving to %@\n", destination);
      [result writeToFile:destination atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
  }
}

char * my_ctime (uint64_t time, char * buffer)
{
  time_t native_time = (time_t) time;
  return ctime_r (&native_time, buffer);
}
@end
