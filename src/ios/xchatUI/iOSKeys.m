//
//  iOSKeys.m
//  xchat UI
//
//  Created by e on 2015/10/03.
//  Copyright © 2015 allnet. All rights reserved.
//

#import "iOSKeys.h"

#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>

@implementation iOSKeys
- (void) createIOSKey {
  [self generateKeyPairPlease];
}

static const UInt8 publicKeyIdentifier[] = "org.alnt.sample.publickey\0";
static const UInt8 privateKeyIdentifier[] = "org.alnt.sample.privatekey\0";

- (void)generateKeyPairPlease
{
  OSStatus status = noErr;
  NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
  NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
  NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
  // 2
  
  NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier
                                      length:strlen((const char *)publicKeyIdentifier)];
  NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier
                                       length:strlen((const char *)privateKeyIdentifier)];
  // 3
  
  SecKeyRef publicKey = NULL;
  SecKeyRef privateKey = NULL;                                // 4
  
  [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA
                  forKey:(__bridge id)kSecAttrKeyType]; // 5
  [keyPairAttr setObject:[NSNumber numberWithInt:4096]
                  forKey:(__bridge id)kSecAttrKeySizeInBits]; // 6
  
  [privateKeyAttr setObject:[NSNumber numberWithBool:NO]
                     forKey:(__bridge id)kSecAttrIsPermanent]; // 7
  [privateKeyAttr setObject:privateTag
                     forKey:(__bridge id)kSecAttrApplicationTag]; // 8
  
  [publicKeyAttr setObject:[NSNumber numberWithBool:NO]
                    forKey:(__bridge id)kSecAttrIsPermanent]; // 9
  [publicKeyAttr setObject:publicTag
                    forKey:(__bridge id)kSecAttrApplicationTag]; // 10
  
  [keyPairAttr setObject:privateKeyAttr
                  forKey:(__bridge id)kSecPrivateKeyAttrs]; // 11
  [keyPairAttr setObject:publicKeyAttr
                  forKey:(__bridge id)kSecPublicKeyAttrs]; // 12
  
  status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr,
                              &publicKey, &privateKey); // 13
  //    error handling...
  [self queryKey:publicTag];
  
  if(publicKey) CFRelease(publicKey);
  if(privateKey) CFRelease(privateKey);                       // 14
}

- (void) queryKey: (NSData *) publicTag {
  // NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *) publicKeyIdentifier)];
  
  // Now lets extract the public key - build query to get bits
  NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
  
  [queryPublicKey setObject:(id)kSecClassKey
                     forKey:(id)kSecClass];
  [queryPublicKey setObject:publicTag
                     forKey:(id)kSecAttrApplicationTag];
  [queryPublicKey setObject:(id)kSecAttrKeyTypeRSA
                     forKey:(id)kSecAttrKeyType];
  [queryPublicKey setObject:[NSNumber numberWithBool:YES]
                     forKey:(id)kSecReturnData];
  
  NSData * publicKeyBits;
  OSStatus err = SecItemCopyMatching((CFDictionaryRef)queryPublicKey, (void *)&publicKeyBits);
  if (err == noErr)
    NSLog(@"successfully got the key, %lu bits\n", (unsigned long)publicKeyBits.length);
  else
    NSLog(@"did not get the key for tag %s\n", publicKeyIdentifier);
}

@end
