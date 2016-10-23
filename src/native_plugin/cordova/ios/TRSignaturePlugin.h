#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface TRSignaturePlugin : CDVPlugin

- (void)sign:(CDVInvokedUrlCommand *)command;
- (void)verify:(CDVInvokedUrlCommand *)command;
- (void)genKeyPairIfNecessary:(CDVInvokedUrlCommand *)command;
- (void)getPublicKey:(CDVInvokedUrlCommand *)command;

@end
