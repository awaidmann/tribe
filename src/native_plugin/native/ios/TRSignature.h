#import <Foundation/Foundation.h>

@interface TRSignature : NSObject

+ (bool)verifyData:(NSDictionary *)data pubKeyStr:(NSString *)pubKeyStr signerID:(NSString *)signerID;
+ (NSDictionary *)signData:(NSDictionary *)data signingKeyID:(NSString *)signingKeyID signerID:(NSString *)signerID lastModified:(long long)lastModified;

@end
