//
//  AppDelegate.m
//  xchat UI
//
//  Created by e on 2015/04/25.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import "AppDelegate.h"
#import "UserNotifications/UserNotifications.h"
#import "UserNotifications/UNUserNotificationCenter.h"

#include <unistd.h>
#include <sys/param.h>
#include <pthread.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "lib/app_util.h"
#include "lib/packet.h"
#import "iOSKeys.h"

#include <syslog.h>   // for the syslog test

@interface AppDelegate ()
- (void) createAllNetDir;

@end

@implementation AppDelegate

extern void acache_save_data ();
static int isSuspended = NO;
static int isInForeground = NO;  // initial state
static int authorizations_granted = 0;

#ifdef USE_ABLE_TO_CONNECT
static int able_to_connect ()
{
  int sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr ("127.0.0.1");
  sin.sin_port = ALLNET_LOCAL_PORT;
  if (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) == 0) {
    close (sock);
    NSLog(@"allnet task still running, will not restart\n");
    return 1;
  }
  NSLog(@"allnet task is not running\n");
  return 0;
}
#endif /* USE_ABLE_TO_CONNECT */

- (void) start_allnet:(UIApplication *) application start_everything:(BOOL)first_call {
  static UIBackgroundTaskIdentifier task;
  if (! first_call) {   // no point in calling until after we start allnet
    sleep (1);          // give time to restart
#ifdef USE_ABLE_TO_CONNECT
    if (able_to_connect ())  // daemons should still be running, sockets should still be open
      return;
    extern void stop_allnet_threads ();  // from astart.c
    NSLog(@"calling stop_allnet_threads\n");
    stop_allnet_threads ();
    sleep (1);
#endif /* USE_ABLE_TO_CONNECT */
    NSLog(@"reconnecting xcommon to alocal\n");
    [self.xChat reconnect];
    [self.conversation setSocket:[self.xChat getSocket]];
    sleep (1);
  }
  // see https://developer.apple.com/library/ios/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/BackgroundExecution/BackgroundExecution.html#//apple_ref/doc/uid/TP40007072-CH4-SW1
  task = [application beginBackgroundTaskWithExpirationHandler:^{
    NSLog(@"allnet task ending background task (started by calling astart_main)\n");
    acache_save_data ();
    [self.xChat disconnect];
    isSuspended = 1;
    [application endBackgroundTask:task];
    task = UIBackgroundTaskInvalid;
  }];
  if (first_call) {
    NSLog(@"calling astart_main\n");
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
      extern int astart_main (int argc, char ** argv);
      char * args [] = { "allnet", "-v", "def", NULL };
      astart_main(3, args);
      NSLog(@"astart_main has completed\n");
    });
    NSLog(@"astart_main should be running\n");
  }
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
  syslog(LOG_ALERT | LOG_PERROR, "this is a test of 13/%d", 13);
  // Override point for customization after application launch.
  // NSLog(@"view controllers has %@\n", self.tabBarController.viewControllers);
  self.my_app = application;
  [self createAllNetDir];
  [self start_allnet:application start_everything:YES];
  sleep(1);
  isInForeground = YES;
  // NSLog(@"creating iOS key\n");
  // [[iOSKeys alloc] createIOSKey];
  // NSLog(@"done creating iOS key\n");
  
  // adapted from http://stackoverflow.com/questions/14834506/detect-low-battery-warning-ios
  UIDevice *device = [UIDevice currentDevice];
  device.batteryMonitoringEnabled = YES;
  [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(batteryChangedNotification) name:@"UIDeviceBatteryStateDidChangeNotification" object:device];
  // adapted from http://hayageek.com/ios-background-fetch/
  // 30s background interval seems reasonable
  // [[UIApplication sharedApplication] setMinimumBackgroundFetchInterval:30.0];
  // maybe better
  [application setMinimumBackgroundFetchInterval:30.0];

  // request permission to display notifications
  // https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/SupportingNotificationsinYourApp.html#//apple_ref/doc/uid/TP40008194-CH4-SW1
  UNUserNotificationCenter * notificationCenter = [UNUserNotificationCenter currentNotificationCenter];
  // UNUserNotificationCenterDelegate * del = self;
  //UNUserNotificationCenterDelegate * del = self;
  //[notificationCenter setDelegate:del];
  int requests = (UIUserNotificationTypeAlert | UIUserNotificationTypeBadge | UIUserNotificationTypeSound);
  //UNAuthorizationOptions requests = (UNAuthorizationOptionAlert + UNAuthorizationOptionSound + UNAuthorizationOptionBadge);
  NSLog(@"requesting authorizations %x\n", requests);
  // https://stackoverflow.com/questions/24454033/registerforremotenotificationtypes-is-not-supported-in-ios-8-0-and-later  -- I think only needed for ios 9 and earlier
  [application registerUserNotificationSettings:[UIUserNotificationSettings settingsForTypes:requests categories:nil]];
  [notificationCenter requestAuthorizationWithOptions:requests
            completionHandler:^(BOOL granted, NSError * _Nullable error) {
              NSLog(@"authorization completion handler called with granted: %d\n", granted);
              authorizations_granted = granted;
                          // Enable or disable features based on authorization.
            }
   ];
  [notificationCenter removeAllDeliveredNotifications];
  application.applicationIconBadgeNumber = 0;
  
  NSLog(@"didFinishLaunching complete\n");
  // sleep (10);
  // exit (0);
  return YES;
}

- (void)application:(UIApplication *)application didRegisterUserNotificationSettings:(UIUserNotificationSettings *)notificationSettings {
  NSLog(@"authorization received, settings %@, types %lu\n", notificationSettings, (long)notificationSettings.types);
  authorizations_granted = 1;
}

- (void) application:(UIApplication *)application didReceiveLocalNotification:(UILocalNotification *)notification {
  NSLog(@"authorization did receive local notification: %@\n", notification);
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center willPresentNotification:(UNNotification *)notification withCompletionHandler:(void (^)(UNNotificationPresentationOptions options))completionHandler {
  
}
- (void) notifyMessageReceived:(NSString *) contact message: (NSString *) msg{
    // create a notification
    UNMutableNotificationContent* content = [[UNMutableNotificationContent alloc] init];
    // content.title = [NSString localizedUserNotificationStringForKey:contact arguments:nil];
    // content.body = [NSString localizedUserNotificationStringForKey:msg arguments:nil];
    content.title = [[NSString alloc] initWithString:contact];
    content.body = [[NSString alloc] initWithString:msg];
    // trigger it now
    UNTimeIntervalNotificationTrigger * trigger = [UNTimeIntervalNotificationTrigger triggerWithTimeInterval:1 repeats:NO];
    UNNotificationRequest * request = [UNNotificationRequest requestWithIdentifier:@"testRequest" content:content trigger:trigger];
    UNUserNotificationCenter * notificationCenter = [UNUserNotificationCenter currentNotificationCenter];
    [notificationCenter addNotificationRequest:request withCompletionHandler:^(NSError * _Nullable error) {
        if (error != nil) {
            NSLog(@"notification error %@", error.localizedDescription);
        } else {   // later, delete this log message
            NSLog(@"notification for new message %@ from %@ has been delivered\n", msg, contact);
        }
    }];
}

- (void) setXChatValue:(XChat *)xChat {
  self.xChat = xChat;
}

- (void) setConversationValue:(ConversationUITextView *)conversation {
  self.conversation = conversation;
}

- (void) setContactsUITVC: (ContactsUITableViewController *) tvc{
  self.tvc = tvc;
}

// largely from http://stackoverflow.com/questions/11204903/nsurlisexcludedfrombackupkey-apps-must-follow-the-ios-data-storage-guidelines
// store in /Library/Application Support/BUNDLE_IDENTIFIER/allnet
- (void) createAllNetDir {
  // make sure Application Support folder exists
  NSError * error = nil;
  NSURL *applicationSupportDirectory = [[NSFileManager defaultManager] URLForDirectory:NSApplicationSupportDirectory
                                                                              inDomain:NSUserDomainMask
                                                                     appropriateForURL:nil
                                                                                create:YES
                                                                                 error:&error];
  if (error) {
    NSLog(@"unable to create allnet application dir, %@", error);
    return;
  }
  
  NSURL *allnetDir = [applicationSupportDirectory URLByAppendingPathComponent:@"allnet" isDirectory:YES];
  if (![[NSFileManager defaultManager] createDirectoryAtPath:[allnetDir path]
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:&error]) {
    NSLog(@"unable to create allnet dir, %@\n", error);
    return;
  }
  // tell iTunes not to back up the contents of this directory
  BOOL success = [allnetDir setResourceValue:@YES forKey: NSURLIsExcludedFromBackupKey error: &error];
  if(!success){
    NSLog(@"error %@ excluding %@ from backup\n", error, allnetDir);
  }
  NSLog(@"directory %@ should exist, please check\n", allnetDir);
  char buf [MAXPATHLEN + 1];
  getcwd(buf, sizeof(buf));
  NSLog(@"pwd is %s\n", buf);
  char * src = malloc(allnetDir.path.length + 1);
  strcpy(src, allnetDir.path.UTF8String);
  NSLog(@"src is %s, path %s\n", src, allnetDir.path.UTF8String);
  char * toRemove = "/Library/Application Support/allnet";
  size_t slen = strlen(src);
  size_t rlen = strlen(toRemove);
  NSLog(@"comparing %s to %s, %zd %zd\n", src + (slen - rlen), toRemove, slen, rlen);
  if ((slen > rlen) && (memcmp (src + (slen - rlen), toRemove, rlen) == 0))
    src [slen - rlen] = '\0';
  chdir(src);
  NSLog(@"pwd now is %s (%s)\n", getcwd(buf, sizeof(buf)), src);
}

- (void)batteryChangedNotification {
  NSLog(@"new battery state is %d (%d)\n", (int)[UIDevice currentDevice].batteryState, (int)UIDeviceBatteryStateUnplugged);
  set_speculative_computation ([UIDevice currentDevice].batteryState != UIDeviceBatteryStateUnplugged);
}

- (void)applicationWillResignActive:(UIApplication *)application {
  // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
  // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
  set_speculative_computation(0);
  isInForeground = NO;
  if (self.tvc != nil) {
    [self.tvc notifyConversationChange:NO];
  }
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
  // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
  // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
  acache_save_data ();
  set_speculative_computation(0);
  isInForeground = NO;
  if (self.tvc != nil) {
    [self.tvc notifyConversationChange:NO];
  }
  NSLog(@"application entering background\n");
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
  // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
  NSLog(@"application entering foreground\n");
  // background mode (actually suspend) closes all our sockets, so start again
  if (isSuspended)
    [self start_allnet:application start_everything:NO];
  set_speculative_computation([UIDevice currentDevice].batteryState != UIDeviceBatteryStateUnplugged);
  isSuspended = NO;
  isInForeground = YES;
  if (self.tvc != nil) {
    [self.tvc notifyConversationChange:YES];
  }
}

- (BOOL) appIsInForeground {
  NSLog(@"appIsInForeground returning %d\n", isInForeground);
  return isInForeground;
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
  // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
  set_speculative_computation ([UIDevice currentDevice].batteryState != UIDeviceBatteryStateUnplugged);
  if (self.tvc != nil) {
    [self.tvc notifyConversationChange:YES];
  }
  NSLog(@"application entering active state\n");
}

- (void)applicationWillTerminate:(UIApplication *)application {
  // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
  NSLog(@"application entering terminate state\n");
}

- (void)application:(UIApplication *)application performFetchWithCompletionHandler:(void (^)(UIBackgroundFetchResult result))completionHandler {
  NSLog(@"application performFetchWithCompletionHandler called in background\n");
  completionHandler(UIBackgroundFetchResultNewData);
}


@end
