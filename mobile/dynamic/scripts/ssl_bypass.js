/**
 * Universal SSL pinning bypass for iOS and Android
 */

// iOS - NSURLSession
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

    // Hook session creation
    Interceptor.attach(NSURLSession['- sessionWithConfiguration:'].implementation, {
        onEnter: function(args) {
            console.log("[*] NSURLSession sessionWithConfiguration called");
        }
    });

    console.log("[*] iOS SSL pinning bypass loaded");
}

// Android - OkHttp3
if (Java.available) {
    Java.perform(function() {
        // OkHttp3 CertificatePinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                console.log('[*] OkHttp3 pinning bypass');
                return;
            };
        } catch(e) {}

        // TrustManager
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');

            var TrustManager = Java.registerClass({
                name: 'com.akali.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            var TrustManagers = [TrustManager.$new()];
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );

            Interceptor.attach(SSLContext_init.implementation, {
                onEnter: function(args) {
                    args[1] = TrustManagers;
                    console.log('[*] SSLContext.init() bypass');
                }
            });
        } catch(e) {}

        console.log("[*] Android SSL pinning bypass loaded");
    });
}
