#import "ViewController.h"
#include <stdio.h>
#include "async_wake.h"
#include "getipaddr.h"
#include "webserver.h"
#include <pthread.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
  printf("******* received memory warning! ***********\n");
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

- (IBAction)hide:(id)sender {
    NSString *executablePath = [NSString stringWithCString:[[[[NSProcessInfo processInfo] arguments] objectAtIndex:0]
                                                            fileSystemRepresentation] encoding:NSUTF8StringEncoding];
    const char *path = [executablePath UTF8String];
    exploit.hidden = YES;
    NSLog(@"About to run\n");
    run_exploit_and_jailbreak(path);
    NSLog(@"Finished!\n");
    inProgress.hidden = YES;
    borat.hidden = NO;
    connInfo.hidden = NO;
    NSString *string1 = @"ssh root@";
    NSString *string2 = @"\nPassword: alpine\nHTTP server running on port 80";
    NSString *string3 = [[string1 stringByAppendingString:getIPAddress()] stringByAppendingString:string2];
    connInfo.text = string3;
}
@end
