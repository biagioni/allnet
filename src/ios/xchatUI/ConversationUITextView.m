//
//  ConversationUITextView.m
//  xchat UI
//
//  Created by e on 2015/06/14.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import "ConversationUITextView.h"
#import "ConversationViewController.h"
#import "XChat.h"
#import "AppDelegate.h"
#import <CoreText/CoreText.h>
@import UIKit;

#include <sys/stat.h>
#include <pthread.h>
#include "packet.h"
#include "util.h"
#include "store.h"
#include "message.h"
#include "keys.h"
#include "xcommon.h"


@interface ConversationUITextView ()

@property int sock;

@property uint64_t newMessagesFrom;
@property UITextView * messageField;
@property UIButton * sendButton;
@property UILabel * nMessageLabel;
@property int originalFrameHeight;  // zero if keyboard was never displayed
@property int keyboardHeight;       // only valid if keyboardIsDisplayed
@property int originalMessageY;
@property int originalSendButtonY;
@property int originalNMessageLabelY;
@property BOOL keyboardIsDisplayed;
@property float yPosition;
@end

@implementation ConversationUITextView

- (void) initialize: (int) sock messageField:(UITextView *)message sendButton: (UIButton*) button contact: (NSString *) contact decorativeLabel: (UILabel *)newMessageLabel {
   // NSLog(@"superview is %@\n", self.superview);
   self.sock = sock;
   if (contact != nil)
      self.xcontact = strcpy_malloc (contact.UTF8String, "ConversationUITextView initialize contact");
   else
      self.xcontact = strcpy_malloc ("no contact yet", "ConversationUITextView initialize contact II");
   self.newMessagesFrom = last_time_read (self.xcontact);
   self.messageField = message;
   self.sendButton = button;
   self.nMessageLabel = newMessageLabel;
   NSLog(@"set send button to %@\n", button);
   //self.scrollPositionBeforeKeyboardAdjustments = CGPointZero;
   self.originalFrameHeight = 0;
   self.keyboardHeight = 0;
   self.originalMessageY = 0;
   self.originalSendButtonY = 0;
   self.keyboardIsDisplayed = NO;
   scrollToEnd(self);
   // register for notifications that the keyboard is being displayed
   [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(readyToShowKeyboard:)
                                                name:UIKeyboardDidShowNotification//UIKeyboardWillShowNotification
                                              object:self.window];
   // register for notifications that the keyboard is being hidden
   [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(readyToHideKeyboard:)
                                                name: UIKeyboardWillHideNotification
                                              object:self.window];
   //[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(scrollForScreenChange:) name:UIKeyboardDidShowNotification object:self.window];
   [[NSNotificationCenter defaultCenter] addObserver:self
                                            selector:@selector(scrollForScreenChange:)
                                                name:UIDeviceOrientationDidChangeNotification
                                              object:self.window];
   CGFloat sizeBefore = self.contentSize.height;
   [self assignContentForContact];
   CGFloat sizeAfter = self.contentSize.height;
   NSLog(@"size went from %f -> %f for %s\n", sizeBefore, sizeAfter, self.xcontact);
}

- (void) setSocket: (int)sock {
   self.sock = sock;
}

- (void)assignContentForContact {
   // NSLog(@"entering assignContentForContact for contact '%s'\n", self.contact);
   NSMutableAttributedString * content = [[NSMutableAttributedString alloc] initWithString:@""];
   struct message_store_info * messages = NULL;
   int messages_used = 0;
   int messages_allocated = 0;
   list_all_messages (self.xcontact, &messages, &messages_allocated, &messages_used);
   if (messages_used > 0) {
      // NSLog (@"messages %p, %d messages allocated, %d used\n", messages, messages_allocated, messages_used);
      for (int i = 0; i < messages_used; i++) {
         // NSLog (@"adding message %d (%d/%d), '%s'\n", messages_used - i - 1, i, messages_used, messages [messages_used - i - 1].message);
         [content appendAttributedString:makeMessage(messages + (messages_used - i - 1),
                                                     self.newMessagesFrom)];
      }
   }
   if (messages != NULL)
      free_all_messages(messages, messages_used);
   self.attributedText = content;
   // NSLog (@"assignedContentForContact calling scrollToEnd for %s, content height %f\n", self.contact,self.contentSize.height);
   scrollToEnd(self);
   [self setNeedsDisplay];
   // NSLog(@"exiting assignContentForContact for contact '%s', content height %f\n", self.contact, self.contentSize.height);
}

- (void)drawRect:(CGRect)rect {
   [super drawRect:rect];
   NSLog (@"drawRect calling scrollToEnd for %s\n", self.xcontact);
   scrollToEnd(self);
   return;
   CGContextRef context = UIGraphicsGetCurrentContext();
   NSLog(@"current context %@ of w/h %fx%f, our w/h %fx%f @ %f %f, scroll view %@\n",
         context, self.bounds.size.width,
         self.bounds.size.height, rect.size.width, rect.size.height, rect.origin.x, rect.origin.y,
         self);
   if (context == nil)
      return;
   NSLog(@"current text view %@\n", self);
   // return;
   // Flip the coordinate system
   CGContextSetTextMatrix(context, CGAffineTransformIdentity);
   CGContextTranslateCTM(context, 0, self.bounds.size.height);
   CGContextScaleCTM(context, 1.0, -1.0);
   
   self.yPosition = self.bounds.size.height;
   
   NSLog(@"in drawRect, self.contact is %s\n", self.xcontact);
   NSMutableArray * result_messages = [[NSMutableArray alloc] initWithCapacity:1000];
   
   keyset * k;
   int nk = all_keys (self.xcontact, &k);
   // NSMutableAttributedString * text = [[NSMutableAttributedString alloc] init];
   // NSAttributedString * nl = [[NSAttributedString alloc] initWithString:@"\n"];
   // unsigned long long int now = allnet_time();
   for (int ik = 0; ik < nk; ik++) {
      // NSLog(@"starting ik %d, max %d\n", ik, nk);
      struct msg_iter * iter = start_iter (self.xcontact, k [ik]);
      if (iter != NULL) {
         uint64_t seq;
         uint64_t time = 0;
         uint64_t rcvd_time = 0;
         int tz_min;
         char ack [MESSAGE_ID_SIZE];
         char * message = NULL;
         int msize;
         int next = prev_message(iter, &seq, &time, &tz_min, &rcvd_time, ack, &message, &msize);
         while (next != MSG_TYPE_DONE) {
            // NSLog(@"next %d, message %p, msize %d, seq %lld\n", next, message, msize, seq);
            BOOL inserted = false;
            if ((next == MSG_TYPE_RCVD) || (next == MSG_TYPE_SENT)) {  // ignore acks
               struct message_store_info mi;
               if (message != NULL) {
                  mi.message = message;
                  mi.msize = msize;
                  mi.seq = seq;
                  mi.time = time;
                  mi.tz_min = tz_min;
                  mi.msg_type = next;
                  mi.message_has_been_acked = 0;
                  mi.prev_missing = 0;
                  if ((next == MSG_TYPE_SENT) &&
                      (is_acked_one(self.xcontact, k [ik], seq, NULL)))
                     mi.message_has_been_acked = 1;
                  NSObject * mipObject = [NSValue value:(&mi)
                                           withObjCType:@encode(struct message_store_info)];
                  // if messages are mostly ordered, most of the time this loop will be short
                  for (long i = (long)result_messages.count - 1; ((i >= 0) && (! inserted)); i--) {
                     // NSLog(@"i is %ld\n", i);
                     struct message_store_info mi_from_array;
                     [(result_messages [i]) getValue:&mi_from_array];
                     // NSLog(@"i is %ld, mi_from_array is %lld\n", i, mi_from_array.time);
                     if (mi.time <= mi_from_array.time) {  // insert here
                        // NSLog(@"saving: %s %d %lld/%lld at index %ld\n", mi.message, mi.msize, mi.time, mi_from_array.time, i + 1);
                        [result_messages insertObject:mipObject atIndex:i + 1];
                        inserted = true;
                     }
                  }
                  if (! inserted) {  // should save it at the very beginning
                     // NSLog(@"0-saving: %s %d %lld at index 0\n", mi.message, mi.msize, mi.time);
                     [result_messages insertObject:mipObject atIndex:0];
                     inserted = true;
                  }
               }
            }
            if ((! inserted) && (message != NULL))
               free(message);
            message = NULL;
            // NSLog(@"calling prev_message\n");
            next = prev_message(iter, &seq, &time, &tz_min, &rcvd_time, ack, &message, &msize);
            // NSLog(@"prev_message returned %d, %p\n", next, message);
         }
         // NSLog(@"freeing iter %p\n", iter);
         free_iter(iter);
         // NSLog(@"freed iter\n");
      }
   }
   if (nk > 0)  // release the storage for the keys
      free (k);
   uint64_t last_seq = 0;
   NSValue * last_received = NULL;
   for (NSValue * obj in result_messages) {  // add information about missing messages
      struct message_store_info mi;
      [obj getValue:&mi];
      if (mi.msg_type == MSG_TYPE_RCVD) {
         if ((last_seq != 0) && (last_received != NULL) &&
             (mi.seq + 1 < last_seq)) {
            struct message_store_info last_struct;
            [last_received getValue:&last_struct];
            last_struct.prev_missing = (last_seq - mi.seq - 1);
         }
         last_received = obj;
         last_seq = mi.seq;
      }
   }
   for (NSValue * obj in result_messages) {  // create a bubble for each message
      struct message_store_info mi;
      [obj getValue:&mi];
      // NSLog(@"adding mi %s (%p) %d\n", mi.message, mi.message, mi.msize);
      @try {   // initWithUTF8String will fail if the string is not valid UTF8
         BOOL is_new = mi.rcvd_time + (24 * 60 * 60) >= self.newMessagesFrom;
         [self drawBubble:[[NSString alloc] initWithUTF8String:mi.message] msg_type:mi.msg_type is_acked:mi.message_has_been_acked is_new:is_new context:context time:mi.time tzMin: mi.tz_min];
      } @catch (NSException *e) {
         // I don't think this normally happens.  Should check sometime
         NSLog(@"message %s is not valid UTF8, ignoring\n", mi.message);
      }
      free ((void *)mi.message);
   }
   scrollToEnd(self);
}

// inspired from http://stackoverflow.com/questions/4442126/how-to-draw-a-speech-bubble-on-an-iphone
// but not much actual code.
// also from http://www.raywenderlich.com/4147/core-text-tutorial-for-ios-making-a-magazine-app
// and http://stackoverflow.com/questions/8377496/how-to-get-the-real-height-of-text-drawn-on-a-ctframe
- (void)drawBubble:(NSString *) message msg_type:(int)type
          is_acked:(BOOL)acked is_new:(BOOL)is_new context:(CGContextRef)context time:(uint64_t)time tzMin:(int)tzMin {
   
   // NSString* attString = [[NSAttributedString alloc] initWithString:message];//2
   
   NSString * withDate = addDate(message, time, tzMin);
   
   CGRect currentFrame = self.bounds;
   // CGSize selfSize = currentFrame.size;
   // UIGraphicsBeginImageContext(selfSize);
   
   CGRect rectangle;
   rectangle.origin.x = currentFrame.size.width / 4.0f;
   rectangle.origin.y = currentFrame.size.height - self.yPosition;
   rectangle.size.width = currentFrame.size.width * 3.0f / 4.0f;
   rectangle.size.height = currentFrame.size.height;
   
   if (type == MSG_TYPE_RCVD) { // received message
      rectangle.origin.x = 1;
   }
   
   CGMutablePathRef path = CGPathCreateMutable(); //1
   CGPathAddRect(path, NULL, rectangle);
   
   NSAttributedString* attString = [[NSAttributedString alloc] initWithString:withDate];
   
   CTFramesetterRef framesetter = CTFramesetterCreateWithAttributedString((CFAttributedStringRef)attString);
   CTFrameRef frame = CTFramesetterCreateFrame(framesetter, CFRangeMake(0, [attString length]), path, NULL);
   NSArray * lines = (NSArray *) ((__bridge id)CTFrameGetLines(frame));
   
   //Get line origins
   CGPoint lOrigins[TEXTVIEWSIZE];
   CTFrameGetLineOrigins(frame, CFRangeMake(0, 0), lOrigins);
   UIFont * font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
   float actualHeight = lOrigins[0].y - lOrigins[[lines count] - 1].y + font.pointSize;
   // NSLog (@"height is %f (%f, %f) for %@\n", actualHeight, bogusHeight, font.pointSize, message);
   
   CFRelease(frame);
   CFRelease(path);
   CFRelease(framesetter);
   
   // now we know the size of the text, can draw the box
   //rectangle.origin.y += rectangle.size.height - actualHeight;
   rectangle.origin.y += 1;
   rectangle.size.height = actualHeight;
   if ((type == MSG_TYPE_SENT) && (acked))
      CGContextSetFillColorWithColor(context, [[UIColor greenColor] CGColor]);
   else if ((type == MSG_TYPE_RCVD) && (is_new))
      CGContextSetFillColorWithColor(context, [[UIColor cyanColor] CGColor]);
   else
      CGContextSetFillColorWithColor(context, [[UIColor whiteColor] CGColor]);
   CGContextFillRect(context, rectangle);
   CGContextStrokeRect(context, rectangle);
   
   // Now that we know the height and have drawn the box, redraw the text
   CGMutablePathRef path2 = CGPathCreateMutable();
   CGPathAddRect(path2, NULL, rectangle);
   
   CTFramesetterRef framesetter2 =
   CTFramesetterCreateWithAttributedString((CFAttributedStringRef)attString);
   CTFrameRef frame2 = CTFramesetterCreateFrame(framesetter2, CFRangeMake(0, [attString length]), path2, NULL);
   CTFrameDraw(frame2, context);
   // NSLog(@"drawn frame with content %@ (probably at position %f %f)\n", attString, rectangle.origin.x, rectangle.origin.y);
   
   CFRelease(frame2);
   CFRelease(path2);
   CFRelease(framesetter2);
   self.yPosition -= actualHeight + 5;
   // NSLog(@"wrote message %@\n", message);
}

/* copied from store.c */
static char * string_replace (char * original, char * pattern, char * repl)
{
   char * p = strstr (original, pattern);
   if (p == NULL) {
      printf ("error: string %s does not contain '%s'\n", original, pattern);
      /* this is a serious error -- need to figure out what is going on */
      exit (1);
   }
   size_t olen = strlen (original);
   size_t plen = strlen (pattern);
   size_t rlen = strlen (repl);
   size_t size = olen + 1 + rlen - plen;
   char * result = malloc_or_fail (size, "string_replace");
   size_t prelen = p - original;
   memcpy (result, original, prelen);
   memcpy (result + prelen, repl, rlen);
   char * postpos = p + plen;
   size_t postlen = olen - (postpos - original);
   memcpy (result + prelen + rlen, postpos, postlen);
   result [size - 1] = '\0';
   /*  printf ("replacing %s with %s in %s gives %s\n",
    pattern, repl, original, result); */
   return result;
}

// result is malloc'd, must be free'd
static char * contact_last_read_path (char * contact, keyset k)
{
   char * directory = key_dir (k);
   if (directory != NULL) {
      directory = string_replace(directory, "contacts", "xchat");
      char * path = strcat3_malloc(directory, "/", "last_read", "contact_last_read_path");
      free (directory);
      return path;
   }
   return NULL;
}

static void update_time_read (char * contact)
{
   keyset *k;
   int nkeys = all_keys(contact, &k);
   for (int ikey = 0; ikey < nkeys; ikey++) {
      char * path = contact_last_read_path(contact, k [ikey]);
      if (path != NULL) {
         NSLog(@"path is %s\n", path);
         int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
         write(fd, " ", 1);
         close (fd);   /* all we need to do is set the time */
         free (path);
      }
   }
   free (k);
}

static uint64_t last_time_read (char * contact)
{
   keyset *k = NULL;
   uint64_t last_read = 0;
   int nkeys = all_keys(contact, &k);
   for (int ikey = 0; ikey < nkeys; ikey++) {
      char * path = contact_last_read_path(contact, k [ikey]);
      if (path != NULL) {
         // NSLog(@"new path for %s is %s\n", contact, path);
         struct stat st;
         if (stat(path, &st) == 0) {
            if (last_read < st.st_mtimespec.tv_sec)
               last_read = st.st_mtimespec.tv_sec;
         } else {   // last_read file does not exist
            update_time_read(contact);
            last_read = time (NULL);
         }
         free (path);
      }
   }
   if (nkeys > 0)
      free (k);
   static uint64_t delta = 0;
   if (delta == 0)
      delta = time (NULL) - allnet_time();  // record the difference in epoch
   // NSLog(@"for %s last time is %lld/%lld, now %ld/%lld\n", contact, last_read, last_read - delta, time(NULL), allnet_time());
   return last_read - delta;
}

- (void)displayContact: (NSString *) nsStringContact {
   if (nsStringContact == nil)
      return;
   NSLog(@"ConversationUITextView displaying contact %@ (=? %s), %s, %d\n", nsStringContact, nsStringContact.UTF8String, self.xcontact, strcmp(self.xcontact, nsStringContact.UTF8String));
   if ((self.xcontact == NULL) || (strcmp(self.xcontact, nsStringContact.UTF8String) != 0)) {
      if (self.xcontact != NULL) {   // new contact
         update_time_read(self.xcontact);
         free (self.xcontact);
      }
      self.xcontact = strcpy_malloc(nsStringContact.UTF8String, "ConversationUITextView.m displayContact");
   }
   // initialize the send button for sending messages
   [self.sendButton addTarget:self action:@selector(messageEntered:) forControlEvents: UIControlEventTouchUpInside]; //UIControlEventEditingDidEndOnExit];
   [self.sendButton addTarget:self action:@selector(readyToHideKeyboard:) forControlEvents: UIControlEventTouchUpInside]; //UIControlEventEditingDidEndOnExit];
   [self assignContentForContact];
   [self setNeedsDisplay];
   // set the last time read
   self.newMessagesFrom = last_time_read (self.xcontact);
   NSLog(@"set newMessagesFrom to %llu\n", self.newMessagesFrom);
   //NSLog(@"set target for text message field\n");
}

static void scrollToEnd (UITextView * tv) {
   if (tv.contentSize.height > tv.frame.size.height) {
      CGPoint offset;
      offset.x = 0;
      offset.y = tv.contentSize.height - tv.frame.size.height;
      [tv setContentOffset:offset];
      // NSLog(@"scrolled rect to %f = %f - %f, text view %@\n", offset.y, tv.contentSize.height, tv.frame.size.height, tv);
   } else {
      NSLog(@"scrollToEnd did nothing since content height %f <= frame height %f\n",
            tv.contentSize.height, tv.frame.size.height);
   }
}

// delta_minutes and local_time_offset are copied from cutil.c

/* only really works within 24 hours -- otherwise, too complicated */
/* should use mktime, but does not translate GMT/UTC time */
static int delta_minutes (struct tm * local, struct tm * gm)
{
   int delta_hour = local->tm_hour - gm->tm_hour;
   if (local->tm_wday == ((gm->tm_wday + 8) % 7)) {
      delta_hour += 24;
   } else if (local->tm_wday == ((gm->tm_wday + 6) % 7)) {
      delta_hour -= 24;
   } else if (local->tm_wday != gm->tm_wday) {
      printf ("assertion error: weekday %d != %d +- 1\n",
              local->tm_wday, gm->tm_wday);
      exit (1);
   }
   int delta_min = local->tm_min - gm->tm_min;
   if (delta_min < 0) {
      delta_hour -= 1;
      delta_min += 60;
   }
   int result = delta_hour * 60 + delta_min;
   /*
    printf ("delta minutes is %02d:%02d = %d\n", delta_hour, delta_min, result);
    */
   return result;
}

/* returns the number of minutes between local time and UTC,
 * as a signed integer */
static int local_time_offset ()
{
   time_t now = time (NULL);
   
   struct tm now_ltime_tm;
   localtime_r (&now, &now_ltime_tm);
   struct tm gtime_tm;
   gmtime_r (&now, &gtime_tm);
   /*
    printf ("local time %s", asctime (&now_ltime_tm));
    printf ("   gm time %s", asctime (&gtime_tm));
    printf ("local time %d:%02d:%02d, gm time %d:%02d:%02d\n",
    now_ltime_tm.tm_hour, now_ltime_tm.tm_min, now_ltime_tm.tm_sec,
    gtime_tm.tm_hour, gtime_tm.tm_min, gtime_tm.tm_sec);
    printf ("local time offset %d\n", delta_minutes (&now_ltime_tm, &gtime_tm));
    */
   return (delta_minutes (&now_ltime_tm, &gtime_tm));
}

static NSString * basicDate (uint64_t time, int tzMin) {
   // objective C time begins on January 1st, 2001.  allnet time begins on January 1st, 2000.
   uint64_t unixTime = time + ALLNET_Y2K_SECONDS_IN_UNIX;
   NSDate * date = [[NSDate alloc] initWithTimeIntervalSince1970:unixTime];
   // date formatter code from https://developer.apple.com/library/ios/documentation/Cocoa/Conceptual/DataFormatting/Articles/dfDateFormatting10_4.html#//apple_ref/doc/uid/TP40002369-SW1
   NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
   [dateFormatter setDateStyle:NSDateFormatterMediumStyle];
   [dateFormatter setTimeStyle:NSDateFormatterMediumStyle];
   NSString * dateString = [dateFormatter stringFromDate:date];
   if (local_time_offset() != tzMin) {
      // some of this code from cutil.c
      int delta = tzMin - local_time_offset();
      while (delta < 0)
         delta += 0x10000;  // 16-bit value
      if (delta >= 0x8000)
         delta = 0x10000 - delta;
      NSString * offset = [[NSString alloc] initWithFormat:@" (%+d:%d)", delta / 60, delta % 60];
      [dateString stringByAppendingString:offset];
   }
   dateString = [dateString stringByAppendingString:@"\n"];
   return dateString;
}

static NSString * addDate (NSString * s, uint64_t time, int tzMin) {
   NSString * dateString = basicDate(time, tzMin);
   dateString = [dateString stringByAppendingString:s];
   dateString = [dateString stringByAppendingString:@"\n"];
   // NSLog(@"date string is '%@'\n", dateString);
   // 2015-10-20 20:42:46.037 xchat UI[3077:85323] date string is 'Oct 20, 2015, 7:14:08 PM
   // how about a really really really loooooooong message, what happens then?
   // '
   return dateString;
}

#if 0
static NSAttributedString * alignColorDate (const char * original, Boolean green, Boolean right,
                                            uint64_t time, int tz_min) {
   NSString * s = [[NSString alloc] initWithUTF8String:original];
   s = [s stringByAppendingString:@"\n"];
   NSAttributedString * withDate = [[NSAttributedString alloc]
                                    initWithString:addDate(s, time, tz_min)];
   NSMutableAttributedString * result = [[NSMutableAttributedString alloc]
                                         initWithAttributedString:withDate];
   NSDictionary * att = [NSDictionary
                         dictionaryWithObject: UIColor.greenColor
                         forKey: NSBackgroundColorAttributeName];
   if (green)
      [result addAttributes:att range:NSMakeRange(0,[result length])];
   NSMutableParagraphStyle * alignment = [[NSMutableParagraphStyle alloc] init];
   if (right)
      [alignment setAlignment:NSTextAlignmentRight];
   else
      [alignment setAlignment:NSTextAlignmentLeft];
   [result addAttributes:[NSDictionary dictionaryWithObject:alignment forKey:NSParagraphStyleAttributeName] range:NSMakeRange(0,[result length])];
   return result;
}
#endif /* 0 */

static NSAttributedString * makeMessage (struct message_store_info * info, uint64_t now) {
   NSString * s = [[NSString alloc] initWithUTF8String:info->message];
   NSMutableAttributedString * result = [[NSMutableAttributedString alloc] initWithString:s];
   UIColor * background = UIColor.whiteColor;
#define SECONDS_PER_DAY     (24 * 60 * 60)      // 86400
   if ((info->msg_type == MSG_TYPE_SENT) && (info->message_has_been_acked))
      background = UIColor.greenColor;
   else if (info->msg_type == MSG_TYPE_RCVD) {
      /* cyan is red=0, green=1, blue=1.  shade the red based on elapsed time */
      double fractionOfDay = 1.0;
      if (info->rcvd_time + SECONDS_PER_DAY >= now) {
         if (now > info->rcvd_time)
            fractionOfDay = (((now - info->rcvd_time) * 1.0) / SECONDS_PER_DAY);
         else  // brand new message
            fractionOfDay = 0.0;
      }
      background = [[UIColor alloc] initWithRed:fractionOfDay green:1 blue:1 alpha:1];
   }
   NSDictionary * att = [NSDictionary
                         dictionaryWithObject: background
                         forKey: NSBackgroundColorAttributeName];
   [result addAttributes:att range:NSMakeRange(0,[result length])];
   NSMutableParagraphStyle * alignment = [[NSMutableParagraphStyle alloc] init];
   if (info->msg_type == MSG_TYPE_SENT)
      [alignment setAlignment:NSTextAlignmentRight];
   else
      [alignment setAlignment:NSTextAlignmentLeft];
   [result addAttributes:[NSDictionary dictionaryWithObject:alignment forKey:NSParagraphStyleAttributeName] range:NSMakeRange(0,[result length])];
   /* [result addAttribute:NSFontAttributeName
    value:[UIFont systemFontOfSize:20.0]
    range:NSMakeRange(0, result.length)]; */
   [result addAttribute:NSFontAttributeName
                  value:[UIFont preferredFontForTextStyle:UIFontTextStyleBody]
                  range:NSMakeRange(0, result.length)];
   [result appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n\n"]];
   // add date
   NSMutableAttributedString * date = [[NSMutableAttributedString alloc]
                                       initWithString: basicDate(info->time, info->tz_min)];
   [date addAttributes:[NSDictionary dictionaryWithObject:alignment forKey:NSParagraphStyleAttributeName] range:NSMakeRange(0,[date length])];
   [result insertAttributedString:date atIndex:0];
   if ((info->msg_type == MSG_TYPE_RCVD) && (info->prev_missing > 0)) {
      // add note about missing messages, with a red background
      UIColor * redBackground = UIColor.redColor;
      NSDictionary * redAtt = [NSDictionary
                               dictionaryWithObject: redBackground
                               forKey: NSBackgroundColorAttributeName];
      NSString * miss = [NSString stringWithFormat:@"(missing %d message%s)",
                         (int)info->prev_missing, ((info->prev_missing == 1) ? "" : "s")];
      NSMutableAttributedString * missing = [[NSMutableAttributedString alloc] initWithString:miss];
      [missing addAttributes:[NSDictionary dictionaryWithObject:alignment forKey:NSParagraphStyleAttributeName] range:NSMakeRange(0,[missing length])];
      [missing addAttributes:redAtt range:NSMakeRange(0,[missing length])];
      NSMutableAttributedString * newline = [[NSMutableAttributedString alloc] initWithString:@"\n"];
      [missing insertAttributedString:newline atIndex:0];  // add a newline before and two after
      [missing appendAttributedString:newline];
      [missing appendAttributedString:newline];
      [result insertAttributedString:missing atIndex:0];
   }
   return result;
}

struct data_to_send {
   int sock;
   char * contact;
   char * message;
   size_t mlen;
};

static void * send_message_thread (void * arg)
{
   struct data_to_send * d = (struct data_to_send *) arg;
   int sock = d->sock;
   char * contact = d->contact;
   char * message = d->message;
   int mlen = (int)(d->mlen);
   free (arg);
   uint64_t seq = 0;
   pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
   pthread_mutex_lock (&lock);
   NSLog(@"sending message to %s, socket %d\n", contact, sock);
   while (1) {    // repeat until the message is sent
      seq = send_data_message(sock, contact, message, mlen);
      if (seq != 0)
         break;   // message sent
      NSLog (@"result of send_data_message is 0, socket is %d\n", sock);
   }
   NSLog(@"message sent, result %" PRIu64 ", socket %d\n", seq, sock);
   pthread_mutex_unlock (&lock);
   free (contact);
   free (message);
   return (void *) seq;
}

static void send_message_in_separate_thread (int sock, char * contact, char * message, size_t mlen)
{
   struct data_to_send * d = malloc_or_fail(sizeof (struct data_to_send), "send_message_with_delay");
   d->sock = sock;
   d->contact = strcpy_malloc (contact, "send_message_with_delay contact");
   d->message = memcpy_malloc(message, mlen, "send_message_with_delay message");
   d->mlen = mlen;
   pthread_t t;
   if (pthread_create(&t, NULL, send_message_thread, (void *) d) != 0)
      perror ("pthread_create for send_message_with_delay");
}

- (IBAction)messageFieldSelected:(id)sender {

}

- (IBAction)messageEntered:(id)sender {
   UITextView * textView = self.messageField;
   NSLog(@"message to send is %@, socket %d, contact %s\n", textView.text, self.sock, self.xcontact);
   if ((textView.text.length > 0) && (self.xcontact != NULL)) {  // don't send empty messages
      char * message_to_send = strcpy_malloc(textView.text.UTF8String, "messageEntered/to_save");
      // in case of multi-character UTF8 characters, strlen gives the number of bytes
      // to send, text.length gives the number of characters, which is less
      size_t length_to_send = strlen(message_to_send); // not textView.text.length
      // send the message, but only after the GUI has had a chance to run
      send_message_in_separate_thread (self.sock, self.xcontact, message_to_send, length_to_send);
      // save the message
      struct message_store_info info;
      bzero (&info, sizeof (info));  // most fields are not used by makeMessage
      info.msg_type = MSG_TYPE_SENT;
      info.message = message_to_send;
      info.msize = length_to_send;
      // NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
      // [dateFormat setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
      // NSDate * epoch = [dateFormat dateFromString:@"2000-01-01 00:00:00"];
      // NSDate * now = [NSDate date];
      info.time = allnet_time();
      info.tz_min = local_time_offset();
      NSAttributedString * displayMessage = makeMessage (&info, info.time);
      NSMutableAttributedString * newText =
      [[NSMutableAttributedString alloc] initWithAttributedString:self.attributedText];
      [newText appendAttributedString:displayMessage];
      self.attributedText = newText;
      textView.text = @"";
      NSLog (@"messageEntered calling scrollToEnd for %s\n", self.xcontact);
      scrollToEnd (self);
      [self setNeedsDisplay];
   }
}

- (void)markAsAcked: (const char *) contact ackNumber: (long long int) ack {
   // NSLog(@"0: marking as acked %lld, contact %s\n", ack, contact);
   if ((self.xcontact != NULL) && (strcmp(contact, self.xcontact) == 0)) {  // same contact as displayed, re-display
      NSString * nsContact = [[NSString alloc] initWithUTF8String:contact];
      [self displayContact:nsContact];
      // [self setNeedsDisplay];
   }
}

- (NSString *)selectedContact {
   // NSLog(@"self.window %@, self.superview %@, self.contact %s\n", self.window, self.superview, self.contact);
   // if (self.window != nil)
   // NSLog(@"hidden %d %d\n\n", self.window.hidden, self.superview.hidden);
   if ((self.window != nil) && (! self.window.hidden) && (self.xcontact != NULL))
      return [[NSString alloc] initWithUTF8String:self.xcontact];
   return nil;
}

// much of the keyboard code copied from or inspired by http://stackoverflow.com/questions/1126726/how-to-make-a-uitextfield-move-up-when-keyboard-is-present and https://developer.apple.com/library/ios/documentation/StringsTextFonts/Conceptual/TextAndWebiPhoneOS/KeyboardManagement/KeyboardManagement.html

- (void)readyToShowKeyboard:(NSNotification *)notification {
   if (self.keyboardIsDisplayed)
      return;
   NSDictionary* userInfo = [notification userInfo];
   
   // get the height of the keyboard
   int keyboardHeight = [[userInfo objectForKey:UIKeyboardFrameBeginUserInfoKey]
                         CGRectValue].size.height - 53;
   NSLog(@"keyboard height is %d, text y is %d, height %d\n", keyboardHeight, (int)(self.frame.origin.y), (int)(self.frame.size.height));
   // check out http://stackoverflow.com/questions/1126726/how-to-make-a-uitextfield-move-up-when-keyboard-is-present/21096604#21096604
   CGRect scrollViewFrame = self.frame;
   NSLog(@"initial view frame %f %f %f %f\n", scrollViewFrame.origin.x, scrollViewFrame.origin.y, scrollViewFrame.size.width, scrollViewFrame.size.height);
   self.originalFrameHeight = scrollViewFrame.size.height;
   self.keyboardHeight = keyboardHeight;
   if (scrollViewFrame.size.height > keyboardHeight)
      scrollViewFrame.size.height -= keyboardHeight;
   else
      scrollViewFrame.size.height = 0;
   // NSLog (@"frame height %d -> %d\n", self.originalFrameHeight, (int)scrollViewFrame.size.height);
   [self setFrame:scrollViewFrame];
   CGRect messageFrame = self.messageField.frame;
   NSLog (@"message frame is %f x %f @ %f %f\n", messageFrame.size.width, messageFrame.size.height, messageFrame.origin.x, messageFrame.origin.y);
   self.originalMessageY = messageFrame.origin.y;
   messageFrame.origin.y -= keyboardHeight;
   [self.messageField setFrame:messageFrame];
   CGRect sendButtonFrame = self.sendButton.frame;
   self.originalSendButtonY = sendButtonFrame.origin.y;
   sendButtonFrame.origin.y -= keyboardHeight;
   [self.sendButton setFrame:sendButtonFrame];
   CGRect nMessageLabelFrame = self.nMessageLabel.frame;
   self.originalNMessageLabelY = nMessageLabelFrame.origin.y;
   nMessageLabelFrame.origin.y -= keyboardHeight;
   [self.nMessageLabel setFrame:nMessageLabelFrame];
   
   self.keyboardIsDisplayed = YES;
   NSLog(@"set scroll view frame to %f %f %f %f, %@\n", scrollViewFrame.origin.x, scrollViewFrame.origin.y, scrollViewFrame.size.width, scrollViewFrame.size.height, self);
   scrollToEnd(self);
}

- (void)scrollForScreenChange:(NSNotification *)notification {
   if (self.keyboardIsDisplayed) {
      [self readyToHideKeyboard:notification];
      [self readyToShowKeyboard:notification];
   } else {
      NSLog (@"scrollForScreenChange calling scrollToEnd for %s\n", self.xcontact);
      scrollToEnd(self);
   }
}

- (void)readyToHideKeyboard:(NSNotification *)notification {
   if (! self.keyboardIsDisplayed)
      return;
   [self.messageField endEditing:YES];
   CGRect scrollViewFrame = self.frame;
   scrollViewFrame.size.height = self.originalFrameHeight;
   [self setFrame:scrollViewFrame];
   CGRect messageFrame = self.messageField.frame;
   messageFrame.origin.y = self.originalMessageY;
   [self.messageField setFrame:messageFrame];
   CGRect sendButtonFrame = self.sendButton.frame;
   sendButtonFrame.origin.y = self.originalSendButtonY;
   [self.sendButton setFrame:sendButtonFrame];
   CGRect nMessageLabelFrame = self.nMessageLabel.frame;
   nMessageLabelFrame.origin.y = self.originalNMessageLabelY;
   [self.nMessageLabel setFrame:nMessageLabelFrame];

   NSLog(@"hiding keyboard, original frame height %d, set frame to %f %f %f %f, sv %@\n", self.originalFrameHeight, scrollViewFrame.origin.x, scrollViewFrame.origin.y, scrollViewFrame.size.width, scrollViewFrame.size.height, self);
   self.keyboardIsDisplayed = NO;
}

@end
