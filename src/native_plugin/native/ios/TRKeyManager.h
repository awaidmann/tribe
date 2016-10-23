#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, TRKeyManagerKeyPair) {
    TRKeyManagerKeyPairGenerated = 1,
    TRKeyManagerKeyPairValid = 0,
    TRKeyManagerKeyPairFailed = -1
};

@interface TRKeyManager : NSObject

+ (NSInteger)generateKeyPairIfNecessary:(NSString *)uid;

+ (NSString *)publicKeyWithUid:(NSString *)uid;
+ (SecKeyRef)publicKeyFromString:(NSString *)pemPublicKey keyID:(NSString *)keyID;
+ (SecKeyRef)publicKeyRefWithUid:(NSString *)uid;
+ (SecKeyRef)privateKeyRefWithUid:(NSString *)uid;

@end
