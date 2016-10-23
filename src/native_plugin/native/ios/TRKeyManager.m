#import "TRKeyManager.h"
#import "Tribe-Swift.h"

#define MAX_ID 1000000
#define kPrevLaunched @"previouslyLaunched"

const NSUInteger kASN1HeaderLength = 26;
const NSUInteger kECKeySize = 256;
const long long kMillInYear = 31536000000;

const NSString *kPEMHeader = @"-----BEGIN PUBLIC KEY-----";
const NSString *kPEMFooter = @"-----END PUBLIC KEY-----";

const NSString *kPubKeyComp = @".pub";
const NSString *kPrivKeyComp = @".priv";
const NSString *kKeyPath = @"com.tribe.plugin.";

@implementation TRKeyManager

+ (NSInteger)generateKeyPairIfNecessary:(NSString *)uid {
    NSString *path = [kKeyPath stringByAppendingString:uid];
    const char *pubkeyID = [[NSString stringWithFormat:@"%@%@", path, kPubKeyComp] cStringUsingEncoding:NSUTF8StringEncoding];
    const char *privkeyID = [[NSString stringWithFormat:@"%@%@", path, kPrivKeyComp] cStringUsingEncoding:NSUTF8StringEncoding];

    NSData *pubTag = [NSData dataWithBytes:pubkeyID length:strlen(pubkeyID)];
    NSData *privTag = [NSData dataWithBytes:privkeyID length:strlen(privkeyID)];

    NSDictionary *keyQuery = @{
                               (id)kSecClass: (id)kSecClassKey,
                               (id)kSecAttrKeyType: (id)kSecAttrKeyTypeEC,
                               (id)kSecAttrApplicationTag: privTag,
                               (id)kSecReturnAttributes: @YES
                               };

    OSStatus status = noErr;

    CFDictionaryRef attributes = nil;
    status = SecItemCopyMatching((CFDictionaryRef)keyQuery, (CFTypeRef *)&attributes);

    BOOL prevLaunch = [[NSUserDefaults standardUserDefaults] boolForKey:kPrevLaunched];
    if (!prevLaunch) {
        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:kPrevLaunched];
        [self deleteKey:pubTag];
        [self deleteKey:privTag];
        return [self generateKeyPair:uid] ? TRKeyManagerKeyPairGenerated : TRKeyManagerKeyPairFailed;
    } else if (status == errSecItemNotFound) {
        return [self generateKeyPair:uid] ? TRKeyManagerKeyPairGenerated : TRKeyManagerKeyPairFailed;
    } else {
        NSDate *createdOn = (__bridge NSDate *)CFDictionaryGetValue(attributes, kSecAttrCreationDate);

        NSNumber *diff = [NSNumber numberWithDouble: [createdOn timeIntervalSinceNow]];
        NSNumber *year = [NSNumber numberWithLongLong: kMillInYear];

        if (diff >= year) {
            return ([self deleteKey:pubTag] && [self deleteKey:privTag] && [self generateKeyPair:uid]) ? TRKeyManagerKeyPairGenerated : TRKeyManagerKeyPairFailed;
        }

        return TRKeyManagerKeyPairValid;
    }
}

+ (bool)generateKeyPair:(NSString *)uid {

    NSString *path = [kKeyPath stringByAppendingString:uid];
    const char *pubkeyID = [[NSString stringWithFormat:@"%@%@", path, kPubKeyComp] cStringUsingEncoding:NSUTF8StringEncoding];
    const char *privkeyID = [[NSString stringWithFormat:@"%@%@", path, kPrivKeyComp] cStringUsingEncoding:NSUTF8StringEncoding];

    OSStatus status = noErr;

    NSData *pubTag = [NSData dataWithBytes:pubkeyID length:strlen(pubkeyID)];
    NSData *privTag = [NSData dataWithBytes:privkeyID length:strlen(privkeyID)];

    SecKeyRef pubKey = NULL;
    SecKeyRef privKey = NULL;

    NSDictionary *pairAttr = @{
                               (id)kSecAttrKeyType: (id)kSecAttrKeyTypeEC,
                               (id)kSecAttrKeySizeInBits: [NSNumber numberWithInt:kECKeySize],
                               (id)kSecPrivateKeyAttrs:  @{
                                       (id)kSecAttrIsPermanent: @YES,
                                       (id)kSecAttrApplicationTag: privTag
                                       },
                               (id)kSecPublicKeyAttrs: @{
                                       (id)kSecAttrIsPermanent: @YES,
                                       (id)kSecAttrApplicationTag: pubTag
                                       }
                               };

    status = SecKeyGeneratePair((CFDictionaryRef)pairAttr, &pubKey, &privKey);

    if (pubKey) CFRelease(pubKey);
    if (privKey) CFRelease(privKey);

    return (status == errSecSuccess);
}


+ (bool)deleteKey:(NSData *)tag {
    NSDictionary *keyQuery = @{
                               (id)kSecClass: (id)kSecClassKey,
                               (id)kSecAttrKeyType: (id)kSecAttrKeyTypeEC,
                               (id)kSecAttrApplicationTag: tag
                               };
    OSStatus status = noErr;

    status = SecItemDelete((CFDictionaryRef)keyQuery);
    if (status == errSecSuccess || status == errSecItemNotFound) {
        return YES;
    }
    return NO;
}

+ (SecKeyRef)publicKeyFromString:(NSString *)pemPublicKey keyID:(NSString *)keyID {

    OSStatus status = noErr;

    NSMutableArray *keyComps = [NSMutableArray arrayWithArray:[pemPublicKey componentsSeparatedByString:@"\n"]];
    if ([kPEMHeader isEqualToString:[keyComps objectAtIndex:0]]) {
        [keyComps removeObjectAtIndex:0];
    }

    if ([kPEMFooter isEqualToString:[keyComps objectAtIndex:[keyComps count] - 1]]) {
        [keyComps removeObjectAtIndex:[keyComps count] - 1];
    }

    NSMutableData *keyBytes = [[NSMutableData alloc] initWithBase64EncodedString:[keyComps componentsJoinedByString:@""] options: NSDataBase64DecodingIgnoreUnknownCharacters];

    NSRange keySubset = { kASN1HeaderLength,  [keyBytes length] - kASN1HeaderLength };
    keyBytes = [NSMutableData dataWithData:[keyBytes subdataWithRange:keySubset]];

    NSString *randomizedKeyID = [NSString stringWithFormat:@"%@%@_%d", kKeyPath, keyID, arc4random_uniform(MAX_ID)];
    const char *keyPath = [randomizedKeyID cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *keyTag = [NSData dataWithBytes:keyPath length:strlen(keyPath)];

    NSDictionary *keyQuery = @{
                               (id)kSecClass: (id)kSecClassKey,
                               (id)kSecAttrKeyType: (id)kSecAttrKeyTypeEC,
                               (id)kSecAttrApplicationTag: keyTag
                               };
    status = SecItemDelete((CFDictionaryRef)keyQuery);

    NSMutableDictionary *keyAttr = [NSMutableDictionary dictionaryWithDictionary:keyQuery];

    SecKeyRef keyRef = nil;

    if (status == errSecItemNotFound || status == errSecSuccess) {
        [keyAttr addEntriesFromDictionary:@{
                                            (id)kSecValueData: keyBytes,
                                            (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
                                            (id)kSecAttrIsPermanent: @NO,
                                            (id)kSecReturnRef: @YES,
                                            (id)kSecAttrKeySizeInBits: [NSNumber numberWithInteger:kECKeySize]
                                            }];

        SecItemAdd((CFDictionaryRef)keyAttr, (CFTypeRef *)&keyRef);
    }

    return keyRef;
}

+ (NSString *)publicKeyWithUid:(NSString *)uid {
  NSData *pubKey = (NSData *)[TRKeyManager keyFor:uid isPublicKey:YES returnData:YES];
  if (pubKey && [pubKey length] > 0) {
      return [[[CryptoExportImportManager alloc] init] exportPublicKeyToPEM:pubKey keyType:(NSString *)kSecAttrKeyTypeEC keySize:kECKeySize];
  }
  return nil;
}

+ (SecKeyRef)publicKeyRefWithUid:(NSString *)uid {
    return [TRKeyManager keyFor:uid isPublicKey:YES returnData:NO];
}

+ (SecKeyRef)privateKeyRefWithUid:(NSString *)uid {
    return [TRKeyManager keyFor:uid isPublicKey:NO returnData:NO];
}

+ (SecKeyRef)keyFor:(NSString *)uid isPublicKey:(bool)isPublicKey returnData:(bool)returnData {
    NSString *path = [kKeyPath stringByAppendingString:uid];
    const NSString *type = isPublicKey ? kPubKeyComp : kPrivKeyComp;
    const char *keyID = [[NSString stringWithFormat:@"%@%@", path, type] cStringUsingEncoding:NSUTF8StringEncoding];

    NSData *tag = [NSData dataWithBytes:keyID length:strlen(keyID)];
    NSMutableDictionary *keyQuery = [NSMutableDictionary dictionaryWithDictionary:
                                     @{
                                       (id)kSecClass: (id)kSecClassKey,
                                       (id)kSecAttrKeyType: (id)kSecAttrKeyTypeEC,
                                       (id)kSecAttrApplicationTag: tag,
                                       }];
    [keyQuery setObject:@YES forKey:(id)(returnData ? kSecReturnData : kSecReturnRef)];

    SecKeyRef key = nil;
    SecItemCopyMatching((CFDictionaryRef)keyQuery, (CFTypeRef *)&key);

    return key;
}

@end
