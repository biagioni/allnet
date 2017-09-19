//
//  FirstViewController.m
//  xchat UI
//
//  Created by e on 2015/04/25.
//  Copyright (c) 2015 allnet. All rights reserved.
//

#import "FirstViewController.h"

@interface FirstViewController ()

@end

@implementation FirstViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    NSLog(@"view controllers has %@\n", self.tabBarController.viewControllers);

}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
