//Cert Pinning iOS
#import <CommonCrypto/CommonDigest.h>
//----------------------------------
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    ASSERT(nil != connection);
    ASSERT(nil != challenge);
    
    // Use the following to fetch the cert of interest. It will be in PEM format.
    // PEM format is (--BEGIN CERTIFICATE--, --END CERTIFICATE--).
    //     $ echo "Get HTTP/1.0" | openssl s_client -showcerts -connect www.random.org:443
    // Save the certifcate of interest to a file (for example, "random-org.pem").
    //   The certificate is the leaf, and should be located at certifcates[0]. Then, convert
    //   the certifcate to DER.
    //     $ openssl x509 -in "random-org.pem" -inform PEM -out "random-org.der" -outform DER
    
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString: NSURLAuthenticationMethodServerTrust])
    {
        do
        {
            SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
            ASSERT(nil != serverTrust);
            if(!(nil != serverTrust)) break; /* failed */
            
            // SecTrustEvaluate performs customary X509 checks. Unusual conditions (or is it
            // usual for the web?) will cause the function to return *non-success*. Unusual
            // conditions include an expired certifcate or self signed certifcate. Its up to
            // you how to hanlde them. If the certificate is expired or self-signed, it
            // still could be OK since you care about continuity. That is, its the expected
            // certifcte or public key, so everything else from PKI{X} is superfluous.
            OSStatus status = SecTrustEvaluate(serverTrust, NULL);
            ASSERT(errSecSuccess == status);
            if(!(errSecSuccess == status)) break; /* failed */
            
            // The following pins the server's certifcate. A public key would be a better choice
            // since some companies (such as Google) rotate the 'outer' certificate every 30 days
            // or so while the 'inner' public key remains constant.
            // To extract the public key from the SecTrustRef, use SecTrustCopyPublicKey. The
            // call to SecTrustCopyPublicKey *must* occur after SecTrustEvaluate.
            
            SecCertificateRef serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
            ASSERT(nil != serverCertificate);
            if(!(nil != serverCertificate)) break;  /* failed */
            
            CFDataRef serverCertificateData = SecCertificateCopyData(serverCertificate);
            ASSERT(nil != serverCertificateData);
            if(!(nil != serverCertificateData)) break;  /* failed */
            
            [(id)serverCertificateData autorelease];
            const UInt8* const data = CFDataGetBytePtr(serverCertificateData);
            const CFIndex size = CFDataGetLength(serverCertificateData);
            
            ASSERT(nil != data);
            ASSERT(size > 0);
            if(!(nil != data) || !(size > 0)) break; /* failed */
            
            // (lldb) p data
            // (const UInt8 *const) $0 = 0x1af1c980
            // (lldb) p size
            // (CFIndex) $1 = 1647
            // (lldb) po serverCertificateData
            // $2 = 0x1af1c960 <3082066b 30820553 a0030201 02021100 c60ea453 d8b894dd 14bb16dc
            // ... 6b465c0d f0dc8969 7a165371 a32fcddf fbb2e9b9 93b7ab94 1971c53c e56fdd0c e72b00>
            
            NSData* cert1 = [NSData dataWithBytes:data length:(NSUInteger)size];
            ASSERT(nil != cert1);
            if(!(nil != cert1)) break; /* failed */
            
            NSString *file = [[NSBundle mainBundle] pathForResource:@"random-org" ofType:@"der"];
            ASSERT(nil != file);
            if(!(nil != file)) break; /* failed */
            
            NSData* cert2 = [NSData dataWithContentsOfFile:file];
            ASSERT(nil != cert2);
            if(!(nil != cert2)) break; /* failed */
            NSLog(@"cert1:%@,cert2:%@",[self sha1:cert1],[self sha1:cert2]);
            const BOOL equal = [[self sha1:cert1] isEqualToString:[self sha1:cert2]];
            ASSERT(NO != equal);
            if(!(NO != equal)) break; /* failed */
            
            // The only good exit point
            return [[challenge sender] useCredential: [NSURLCredential credentialForTrust: serverTrust]
                          forAuthenticationChallenge: challenge];
            
        } while (0);
    }
    
    
    return [[challenge sender] cancelAuthenticationChallenge: challenge];
}
-(NSString*)sha1:(NSData*)certData {
//returns the SHA1 fingerprint of the cert;
    unsigned char sha1Buffer[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(certData.bytes, certData.length, sha1Buffer);
    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 3];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; ++i)
        [fingerprint appendFormat:@"%02x ",sha1Buffer[i]];
    return [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}
//----------------Add Other Modules Here------------

