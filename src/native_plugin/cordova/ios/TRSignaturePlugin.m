#import "TRSignaturePlugin.h"
#import "TRSignature.h"
#import "TRKeyManager.h"

@implementation TRSignaturePlugin

- (void)sign:(CDVInvokedUrlCommand *)command {
    [[self commandDelegate] runInBackground:^{
        CDVPluginResult *result;

        if ([[command arguments] count] == 4) {
            NSDictionary *toSign = [[command arguments] objectAtIndex: 0];
            NSString *signingKeyID = [[command arguments] objectAtIndex: 1];
            NSString *signerID = [[command arguments] objectAtIndex: 2];
            NSNumber *lastModified = [[command arguments] objectAtIndex: 3];

            NSDictionary *dataWithSig = [TRSignature signData:toSign signingKeyID:signingKeyID signerID:signerID lastModified:[lastModified longLongValue]];
            if (dataWithSig) {
                result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:dataWithSig];
            } else {
                result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Signature creation failed"];
            }
        } else {
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Invalid parameter list"];
        }

        [[self commandDelegate] sendPluginResult:result callbackId:command.callbackId];
    }];
  }

- (void)verify:(CDVInvokedUrlCommand *)command {
    [[self commandDelegate] runInBackground:^{
      CDVPluginResult *result;

      if ([[command arguments] count] == 3) {
        NSDictionary *rawData = [[command arguments] objectAtIndex: 0];
        NSString *publicKey = [[command arguments] objectAtIndex: 1];
        NSString *signerID = [[command arguments] objectAtIndex: 2];

        bool verified = [TRSignature verifyData:rawData pubKeyStr:publicKey signerID:signerID];
        if (verified) {
          result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        } else {
          result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Verification failed"];
        }
      } else {
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Invalid parameter list"];
      }

      [[self commandDelegate] sendPluginResult:result callbackId:command.callbackId];
    }];
}

- (void)genKeyPairIfNecessary:(CDVInvokedUrlCommand *)command {
    [[self commandDelegate] runInBackground:^{
      CDVPluginResult *result;

      if ([[command arguments] count] == 1) {
        NSString *userID = [[command arguments] objectAtIndex: 0];

        NSInteger didCreateKeyPair = [TRKeyManager generateKeyPairIfNecessary:userID];
        if (didCreateKeyPair == TRKeyManagerKeyPairGenerated) {
          result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:YES];
        } else if (didCreateKeyPair == TRKeyManagerKeyPairValid) {
          result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:NO];
        } else {
          result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"Key creation failed"];
        }

      } else {
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Invalid parameter list"];
      }

      [[self commandDelegate] sendPluginResult:result callbackId:command.callbackId];
    }];
}

- (void)getPublicKey:(CDVInvokedUrlCommand *)command {
    [[self commandDelegate] runInBackground:^{
        CDVPluginResult *result;

        if ([[command arguments] count] == 1) {
            NSString *userID = [[command arguments] objectAtIndex: 0];

            NSString *publicKey = [TRKeyManager publicKeyWithUid:userID];
            if (publicKey) {
                result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:publicKey];
            } else {
                result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[NSString stringWithFormat:@"Could not fetch public key for %@", userID]];
            }

        } else {
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Invalid parameter list"];
        }

        [[self commandDelegate] sendPluginResult:result callbackId:command.callbackId];
    }];
}

@end
