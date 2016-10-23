#import "TRSignature.h"
#import "TRKeyManager.h"
#import <CommonCrypto/CommonDigest.h>

NSUInteger kASN1MaxSafeHeaderCount = 16;
//https://en.wikipedia.org/wiki/Decimal_degrees
NSUInteger kMaxDecimalPlaces = 8;

NSString *kTempKeyPath = @"external.pub.user.";
NSString *kSignerProp = @"signerID";
NSString *kLastModifiedProp = @"lastModified";
NSString *kSigProp = @"sig";
NSString *kKeyProp = @"signingKeyID";

@implementation TRSignature

+ (bool)verifyData:(NSDictionary *)data pubKeyStr:(NSString *)pubKeyStr signerID:(NSString *)signerID {
    NSString *signature = [data objectForKey:kSigProp];
    bool verified = NO;

    if (signature) {
        SecKeyRef signerPub = [TRKeyManager publicKeyFromString:pubKeyStr keyID:[kTempKeyPath stringByAppendingString:signerID]];
        NSMutableDictionary *dataWOSig = [NSMutableDictionary dictionaryWithDictionary:data];
        [dataWOSig removeObjectForKey:kSigProp];

        verified = [TRSignature verifySignature:signature data:dataWOSig pubKey:signerPub];
        CFRelease(signerPub);
    }

    return verified;
}

+ (bool)verifySignature:(NSString *)signature data:(NSDictionary *)data pubKey:(SecKeyRef)pubKey {
    OSStatus status = noErr;
    NSData *toValidate = [TRSignature buildSignatureStream:data];

    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([toValidate bytes], (CC_LONG)[toValidate length], digest);

    NSData *sig = [[NSData alloc] initWithBase64EncodedString:signature options:NSDataBase64DecodingIgnoreUnknownCharacters];
    status = SecKeyRawVerify(pubKey,
                             kSecPaddingNone,
                             digest,
                             CC_SHA1_DIGEST_LENGTH,
                             [sig bytes],
                             [sig length]);
    if (status == errSecSuccess) {
        return YES;
    }
    return NO;
}

+ (NSDictionary *)signData:(NSDictionary *)data signingKeyID:(NSString *)signingKeyID signerID:(NSString *)signerID lastModified:(long long)lastModified {
    NSNumber *truncateNano = [NSNumber numberWithLongLong:lastModified];

    NSMutableDictionary *allData = [NSMutableDictionary dictionaryWithDictionary:data];
    [allData setValue:signerID forKey:kSignerProp];
    [allData setValue:truncateNano forKey:kLastModifiedProp];
    [allData setValue:signingKeyID forKey:kKeyProp];

    NSString *signature = [TRSignature signData:allData privKey:[TRKeyManager privateKeyRefWithUid:signerID]];
    [allData setValue:signature forKey:kSigProp];
    return allData;
}

+ (NSString *)signData:(NSDictionary *)data privKey:(SecKeyRef)privKey {
    OSStatus status = noErr;
    NSData *bytes = [TRSignature buildSignatureStream:data];

    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([bytes bytes], (CC_LONG)[bytes length], digest);

    // Signature length is curveSize/8 * 2 + ASN.1 DER Headers
    size_t sigLen =  SecKeyGetBlockSize(privKey)*2 + kASN1MaxSafeHeaderCount;
    uint8_t *sigBuff = malloc(sigLen);

    status = SecKeyRawSign(privKey, kSecPaddingNone, digest, CC_SHA1_DIGEST_LENGTH, sigBuff, &sigLen);

    NSString *encoded;
    if (status == errSecSuccess) {
        encoded = [[[NSData alloc] initWithBytes:sigBuff length:sigLen] base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength | NSDataBase64EncodingEndLineWithLineFeed];
    }
    free(sigBuff);
    return encoded;
}

/*
  All returned types (except objects) are extracted as strings. This way we don't
  have to worry about internal representations of numbers (doubles vs ints) across
  platforms. JSON arrays are not considered here because Firebase has no concept
  of array even if JSON does.

  The keys are then sorted alphabetically to ensure a common serializable specification
  across platforms.

  For every key and value, append 4 NULL(0x0) bytes to the end of it's byte array.
  Nested objects are recursively converted to byte arrays and treated as a if it
  was a single string value. What this means is that you can roughly detect the
  end of a nested object as 2 or more sets of 4 NULLs, depending on the depth.

  The padding scheme was chosen to ensure uniqueness across objects. There is a
  possiblity that a simple byte concatenation without padding could result in a
  collision between objects. For example:

  obj1 = { "a": { "b": 1}}
  obj2 = { "a": "b1" }
  w/o padding:
  obj1 = 0061 0062 0031
  obj2 = 0061 0062 0031

  w/ padding:
  obj1 = 0061 0000 0000 0062 0000 0000 0031 0000 0000 0000 0000
  obj2 = 0061 0000 0000 0062 0031 0000 0000

  The NULL padding was added because the JSON specification does not allow for
  control characters to be sent. Even if a control character is escaped (\0,
  \n, etc..) it will be represented as the literal characters "\" and "0" and not
  it's actual value.
*/

+ (NSData *)buildSignatureStream:(NSDictionary *)data {
    NSNumberFormatter *decFormat = [[NSNumberFormatter alloc] init];
    [decFormat setNumberStyle:NSNumberFormatterDecimalStyle];
    [decFormat setMaximumFractionDigits:kMaxDecimalPlaces];
    [decFormat setRoundingMode:NSNumberFormatterRoundHalfUp];

    NSArray *sortedKeys = [[data allKeys] sortedArrayUsingSelector:@selector(compare:)];
    NSMutableData *sigBytes = [[NSMutableData alloc] init];

    for(NSString *key in sortedKeys) {
        [sigBytes appendData:[key dataUsingEncoding:NSUTF16BigEndianStringEncoding]];
        sigBytes = [TRSignature appendDeliminatorToData:sigBytes];

        NSObject *value = [data valueForKey:key];
        if ([value isKindOfClass:[NSDictionary class]]) {
            [sigBytes appendData:[self buildSignatureStream:(NSDictionary *)value]];
        } else if ([value isKindOfClass:[NSNumber class]]) {
            int numType = CFNumberGetType((CFNumberRef)(NSNumber *)value);
            NSString *numStr;

            if (value == (void*)kCFBooleanFalse || value == (void*)kCFBooleanTrue) {
                // http://stackoverflow.com/questions/2518761/get-type-of-nsnumber
                numStr = [(NSNumber *)value boolValue] ? @"true" : @"false";
            } else if (numType == kCFNumberDoubleType || numType == kCFNumberFloat64Type) {
                numStr = [decFormat stringFromNumber:(NSNumber *)value];
            } else {
                numStr = [NSString stringWithFormat:@"%@", value];
            }
            [sigBytes appendData:[numStr dataUsingEncoding:NSUTF16BigEndianStringEncoding]];

        } else {
            [sigBytes appendData:[[NSString stringWithFormat:@"%@", value] dataUsingEncoding:NSUTF16BigEndianStringEncoding]];
        }
        sigBytes = [TRSignature appendDeliminatorToData:sigBytes];
    }

    return sigBytes;
}

+ (NSMutableData *)appendDeliminatorToData:(NSMutableData *)data {
    UInt8 deliminator[4] = {0, 0, 0, 0};
    [data appendBytes:deliminator length:4];

    return data;
}

@end
