//
//  MoreUIViewController.m
//  xchat UI
//
//  Created by e on 2015/11/08.
//  Copyright © 2015 allnet. All rights reserved.
//

#import "MoreUIViewController.h"
#import "AppDelegate.h"

@interface MoreUIViewController ()

@property UIButton * traceButton;
@property UITextView * traceView;
@property UITextView * broadcastView;

@end

@implementation MoreUIViewController

- (void) viewDidLoad {
  NSLog(@"More viewDidLoad\n");
  [super viewDidLoad];
  self.traceButton = nil;
  self.traceView = nil;
  NSLog(@"More viewDidLoad, subviews are %@\n", self.view.subviews);
  UIScrollView * sv = self.view.subviews [0];
  if ((sv.frame.size.width + sv.frame.origin.x) != self.view.frame.size.width) {
    float newWidth =self.view.frame.size.width - sv.frame.origin.x;
    NSLog (@"scroll view size %f, setting to %f\n", sv.frame.size.width, newWidth);
    CGRect newFrame = sv.frame;
    newFrame.size.width = newWidth;
    [sv setFrame:newFrame];
  }
  NSLog(@"More sub-subviews are %@\n", sv.subviews);
  for (NSObject * item in sv.subviews) {  // create self.traceButton
    // NSLog(@"subview %@\n", item);
    if ((self.traceButton == nil) && ([item isMemberOfClass: [UIButton class]])) {
      UIButton * button = (UIButton *) item;
      NSLog(@"subview %@, title %@\n", item, button.currentTitle);
      if ([button.currentTitle isEqualToString:@"Trace"]) {
        self.traceButton = (UIButton *) item;
        NSLog(@"found trace button\n");
      }
    }
    if ([item isMemberOfClass: [UITextView class]]) {
      UITextView * subtv = (UITextView *) item;
#define TEXT_VIEW_OFFSET    8
      if (subtv.frame.size.width + TEXT_VIEW_OFFSET != sv.frame.size.width) {
        CGRect newFrame = subtv.frame;
        newFrame.size.width = sv.frame.size.width - TEXT_VIEW_OFFSET;
        [subtv setFrame:newFrame];
      }
      if ((subtv.tag == 4) && (self.traceView == nil)) {  // text view for trace
        CGFloat fontSize = [[UIFont preferredFontForTextStyle:UIFontTextStyleBody] lineHeight];
        fontSize *= 0.6;  // make it a little smaller
        NSLog(@"font name is %@\n", subtv.font.fontName);
        UIFont * font = [UIFont fontWithName:subtv.font.fontName size:fontSize];
        [subtv setFont:font];
        self.traceView = subtv;
      } else if ((tv.tag == 5) && (self.broadcastView == nil)) {  // text view for broadcast
        self.broadcastView = subtv;
      }
    }
  }
  if (self.traceButton != nil)
    [self.traceButton addTarget:self action:@selector(traceButtonClicked:) forControlEvents:UIControlEventTouchUpInside];
}

- (void) initializeWindow:(NSString *) contact secret1: (NSString *) s1 secret2: (NSString *) s2 {
  NSLog(@"More initializeWindow\n");
  [self viewDidLoad];
}

static UITextView * tv = nil;

#define START_MESSAGE   "starting trace"

void rcvTrace (const char * trace)
{
  if (tv != nil) {
    if (strcmp (tv.text.UTF8String, START_MESSAGE) == 0)
      tv.text = @"";
    printf ("appending to trace: '%s', width is %f, font x height %f\n", trace, tv.frame.size.width, tv.font.xHeight);
    tv.text = [tv.text stringByAppendingFormat:@"%s", trace];
    [tv setNeedsDisplay];
  }
}

- (void)getInfoFromInterface: (int *)hops_ptr :(int *) details
{
  *hops_ptr = 5;  // default is 5 hops
  *details = 0;   // default is no details
  int counter = 0;
  for (NSObject * item in self.view.subviews) {
    if ([item isMemberOfClass: [UIScrollView class]]) {
      UIScrollView * sv = (UIScrollView *) item;
      int innerCount = 0;
      for (NSObject * inner in sv.subviews) {
        // NSLog (@"scrollview subview %d.%d is %@\n", counter, innerCount, inner);
        if ([inner isMemberOfClass:[UITextField class]]) {
          UITextField * tf = (UITextField *) inner;
          NSLog (@"text field tag is %d, value is %@\n", (int)(tf.tag), tf.text);
          NSInteger fromField = tf.text.integerValue;
          if ((tf.tag == 1) && (fromField > 0) && (fromField <= 255))
            *hops_ptr = (int)fromField;
        } else if ([inner isMemberOfClass:[UISwitch class]]) {
          UISwitch * sw = (UISwitch *) inner;
          if (sw.tag == 2) {
            if (sw.on) {
              NSLog(@"switch is on\n");
              *details = 1;
            } else {
              NSLog(@"switch is off\n");
              *details = 0;
            }
          }
        }
        innerCount++;
      }
    }
    counter++;
  }
}

- (IBAction)traceButtonClicked:(id)sender
{
  NSLog(@"trace button clicked\n");
  [self.view endEditing:YES];   // hide the keyboard, if any
  if (self.traceView != nil) {
    NSLog(@"trace view width is %f -> %f\n", self.view.frame.size.width, self.traceView.frame.size.width);
    if (self.traceView.frame.size.width + TEXT_VIEW_OFFSET != self.view.frame.size.width) {
      CGRect newFrame = self.traceView.frame;
      newFrame.size.width = self.view.frame.size.width - TEXT_VIEW_OFFSET;
      [self.traceView setFrame:newFrame];
    }
    BOOL wide_enough = (self.traceView.frame.size.width >= 500.0f);
    NSLog(@"wide_enough is %s\n", (wide_enough) ? "true" : "false");
    self.traceView.text = @START_MESSAGE;
    [self.traceView setNeedsDisplay];  // but never displayed, only effective after we return
    AppDelegate * appDelegate = (AppDelegate *) [[UIApplication sharedApplication] delegate];
    XChat * socket = appDelegate.xChat;
    int numHops;
    int showDetails;
    [self getInfoFromInterface:(&numHops) :(&showDetails)];
    // NSLog(@"running trace with %d hops\n", numHops);
#define INCREMENTAL_TRACE
#ifdef INCREMENTAL_TRACE
    tv = self.traceView;
    [socket startTrace:&rcvTrace wide:wide_enough maxHops:numHops showDetails:(showDetails != 0)];
#else /* ! INCREMENTAL_TRACE, so wait for the trace before displaying */
    NSString * trace = [socket trace:wide maxHops:numHops];
    self.textView.text = trace;
#endif /* INCREMENTAL_TRACE */
  }
  [self.traceView setNeedsDisplay];
}


@end
