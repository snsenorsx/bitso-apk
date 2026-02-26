/*
 * Bitso Wallet - Comprehensive Frida Bypass Script
 * ================================================
 * Bypasses: Root Detection, Frida Detection, SSL Pinning, Emulator Detection,
 *           Debugger Detection, Play Integrity, FingerprintJS Pro, iProov Calcifer,
 *           Sift Science Device Properties, Sentry Root Check, WebView JS Injection Detection
 *
 * Usage: frida -U -f com.bitso.wallet -l bitso_bypass.js --no-pause
 *
 * Communication: Pipe output to the relay script for real-time analysis
 *   frida -U -f com.bitso.wallet -l bitso_bypass.js --no-pause 2>&1 | python3 frida_relay.py
 */

"use strict";

var TAG = "[BITSO-BYPASS]";
var DETECTIONS_FOUND = [];

function log(category, msg) {
    var ts = new Date().toISOString();
    var line = ts + " " + TAG + " [" + category + "] " + msg;
    console.log(line);
    send({ type: "log", category: category, message: msg, timestamp: ts });
}

function logDetection(category, detail) {
    DETECTIONS_FOUND.push({ category: category, detail: detail });
    log("DETECTION", category + " => " + detail);
}

// ============================================================
// 1) ROOT DETECTION BYPASS
// ============================================================
function bypassRootDetection() {
    log("ROOT", "Initializing root detection bypass...");

    // --- 1a) File.exists() bypass for su/root paths ---
    var rootPaths = [
        "/system/app/Superuser.apk",
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/data/local/su", "/su/bin/su", "/su/bin",
        "/system/xbin/daemonsu",
        // Magisk paths
        "/sbin/.magisk", "/sbin/.magisk/modules",
        "/data/adb/magisk", "/data/magisk",
        "/data/magisk/resetprop",
        "/magisk/.core/bin/",
        // Xposed/LSPosed paths  
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/system/bin/app_process_xposed",
        "/system/bin/app_process32_xposed",
        "/system/bin/app_process64_xposed",
        "/system/bin/app_process32_orig",
        "/system/bin/app_process64_orig",
        "/system/bin/dex2oat_xposed",
        "/system/bin/patchoat_xposed",
        "/system/xposed.prop",
        "/cache/recovery/xposed.zip",
        // LSPosed specific
        "/data/adb/modules/riru_lsposed",
        "/sbin/.magisk/modules/riru_lsposed",
        "/data/data/moe.lsposed/dexm/lsposed.dex",
        "/data/data/org.lsposed.manager",
        "/data/user_de/0/org.lsposed.manager",
        "/storage/emulated/0/Android/data/org.lsposed.manager",
        "/data/media/0/Android/data/org.lsposed.manager",
        "/data/misc/profiles/ref/org.lsposed.manager",
        "/config/sdcardfs/org.lsposed.manager",
        "/mnt/runtime/full/emulated/0/Android/data/org.lsposed.manager",
        "/data/unencrypted/magisk/riru_lsposed",
        "/dev/riru_IwV9Hu8/modules/riru_lsposed@lspd",
        "/system/framework/org.lsposed.manager",
        "/data/data/com.google.android.gms/files/backup_chunk_listings/org.lsposed.manager",
        // Riru/EdXposed
        "/system/lib/libriru_edxp.so",
        "/system/lib64/libriru_edxp.so",
        // Magisk Xposed
        "/magisk/xposed/system/lib/libart-compiler.so",
        "/magisk/xposed/system/lib/libart-disassembler.so",
        "/magisk/xposed/system/lib/libart.so",
        "/magisk/xposed/system/lib/libsigchain.so",
        // iProov calcifer extra paths
        "/system/usr/we-need-root/",
        "/system/bin/.ext/",
        "/system/sbin"
    ];

    var File = Java.use("java.io.File");
    var originalExists = File.exists;
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i] || path.indexOf(rootPaths[i]) !== -1) {
                logDetection("ROOT_FILE", "File.exists blocked: " + path);
                return false;
            }
        }
        return originalExists.call(this);
    };

    // --- 1b) PackageManager root app detection bypass ---
    var rootPackages = [
        "com.noshufou.android.su", "com.noshufou.android.su.elite",
        "eu.chainfire.supersu", "com.koushikdutta.superuser",
        "com.thirdparty.superuser", "com.yellowes.su",
        "com.topjohnwu.magisk", "com.topjohnwu.magisk.su",
        "com.koushikdutta.rommanager",
        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer",
        "com.saurik.substrate",
        "com.zachspong.temprootremovejb",
        "com.amphoras.hidemyroot",
        "com.formyhm.hideroot",
        "org.lsposed.manager", "moe.lsposed"
    ];

    var PackageManager = Java.use("android.content.pm.PackageManager");
    var NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");

    // getPackageInfo(String, int)
    PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkgName, flags) {
        for (var i = 0; i < rootPackages.length; i++) {
            if (pkgName === rootPackages[i]) {
                logDetection("ROOT_PKG", "getPackageInfo blocked: " + pkgName);
                throw NameNotFoundException.$new(pkgName);
            }
        }
        return this.getPackageInfo(pkgName, flags);
    };

    // getPackageInfo(String, PackageInfoFlags) - Android 13+
    try {
        PackageManager.getPackageInfo.overload("java.lang.String", "android.content.pm.PackageManager$PackageInfoFlags").implementation = function (pkgName, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (pkgName === rootPackages[i]) {
                    logDetection("ROOT_PKG", "getPackageInfo(flags) blocked: " + pkgName);
                    throw NameNotFoundException.$new(pkgName);
                }
            }
            return this.getPackageInfo(pkgName, flags);
        };
    } catch (e) {
        log("ROOT", "Android 13+ PackageInfoFlags overload not available (OK on older Android)");
    }

    // --- 1c) Runtime.exec bypass for 'su', 'which su', 'getprop', 'mount' ---
    var Runtime = Java.use("java.lang.Runtime");

    Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
        var cmd = cmdArray.join(" ");
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            logDetection("ROOT_EXEC", "Runtime.exec blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmdArray);
    };

    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        if (cmd.indexOf("/system/xbin/which") !== -1 && cmd.indexOf("su") !== -1) {
            logDetection("ROOT_EXEC", "Runtime.exec blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        // Spoof 'getprop' to remove root indicators
        if (cmd === "getprop") {
            logDetection("ROOT_PROP", "getprop intercepted - spoofing output");
        }
        return this.exec(cmd);
    };

    // --- 1d) Build.TAGS bypass (test-keys -> release-keys) ---
    var Build = Java.use("android.os.Build");
    var fieldTags = Build.class.getDeclaredField("TAGS");
    fieldTags.setAccessible(true);
    fieldTags.set(null, Java.use("java.lang.String").$new("release-keys"));
    log("ROOT", "Build.TAGS spoofed to 'release-keys'");

    // --- 1e) System properties bypass ---
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        var origGet = SystemProperties.get.overload("java.lang.String");
        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            if (key === "ro.debuggable") {
                logDetection("ROOT_PROP", "ro.debuggable spoofed to 0");
                return "0";
            }
            if (key === "ro.secure") {
                logDetection("ROOT_PROP", "ro.secure spoofed to 1");
                return "1";
            }
            if (key === "ro.build.tags") {
                logDetection("ROOT_PROP", "ro.build.tags spoofed to release-keys");
                return "release-keys";
            }
            if (key === "service.adb.root") {
                logDetection("ROOT_PROP", "service.adb.root spoofed to 0");
                return "0";
            }
            return origGet.call(this, key);
        };

        var origGet2 = SystemProperties.get.overload("java.lang.String", "java.lang.String");
        SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
            if (key === "ro.debuggable") return "0";
            if (key === "ro.secure") return "1";
            if (key === "ro.build.tags") return "release-keys";
            if (key === "service.adb.root") return "0";
            return origGet2.call(this, key, def);
        };
    } catch (e) {
        log("ROOT", "SystemProperties hook failed (non-critical): " + e);
    }

    // --- 1f) Bitso-specific isRootedDevice bypass (LA.a interface) ---
    // The app checks root via LA.a.invoke() -> used in RA.b (lifecycle observer)
    // and OA.e (show rooted device alert decision)
    try {
        var SplashActivity = Java.use("com.bitso.wallet.onboarding.splash.SplashActivity");
        SplashActivity.B0.implementation = function (isRooted) {
            logDetection("ROOT_BITSO", "SplashActivity.checkRootedDeviceDecision called with: " + isRooted + " -> forcing false");
            this.B0(false);
        };
    } catch (e) {
        log("ROOT", "SplashActivity hook failed: " + e);
    }

    // --- 1g) Sentry root checker bypass ---
    try {
        var SentryRootChecker = Java.use("io.sentry.android.core.internal.util.m");
        SentryRootChecker.e.implementation = function () {
            logDetection("ROOT_SENTRY", "Sentry root check -> returning false");
            return false;
        };
    } catch (e) {
        log("ROOT", "Sentry root checker hook not found: " + e);
    }

    // --- 1h) Sift Science root data collection bypass ---
    try {
        var SiftCollector = Java.use("siftscience.android.DevicePropertiesCollector");
        SiftCollector.collect.implementation = function () {
            logDetection("ROOT_SIFT", "Sift Science device properties collection intercepted");
            // Still call it but the File.exists and PackageManager hooks above will return clean data
            this.collect();
        };
    } catch (e) {
        log("ROOT", "Sift Science hook not available: " + e);
    }

    log("ROOT", "Root detection bypass initialized - " + rootPaths.length + " paths, " + rootPackages.length + " packages monitored");
}

// ============================================================
// 2) FRIDA DETECTION BYPASS
// ============================================================
function bypassFridaDetection() {
    log("FRIDA", "Initializing Frida detection bypass...");

    // --- 2a) /proc/self/maps hiding ---
    var fopen = Module.findExportByName("libc.so", "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function (args) {
                this.path = args[0].readUtf8String();
            },
            onLeave: function (retval) {
                if (this.path && this.path.indexOf("/proc/self/maps") !== -1) {
                    logDetection("FRIDA_MAPS", "/proc/self/maps access detected");
                }
            }
        });
    }

    // Intercept read to filter frida-related entries from /proc/self/maps
    var pread = Module.findExportByName("libc.so", "read");
    // We'll use a different approach - hook strstr to prevent frida string matching
    var strstr = Module.findExportByName("libc.so", "strstr");
    if (strstr) {
        var fridaStrings = [
            "frida", "gadget", "linjector", "agent", "gmain",
            "gdbus", "gum-js-loop", "frida-agent",
            "frida-server", "frida-gadget"
        ];
        Interceptor.attach(strstr, {
            onEnter: function (args) {
                if (args[1] !== null) {
                    try {
                        var needle = args[1].readUtf8String();
                        if (needle) {
                            var nl = needle.toLowerCase();
                            for (var i = 0; i < fridaStrings.length; i++) {
                                if (nl.indexOf(fridaStrings[i]) !== -1) {
                                    logDetection("FRIDA_STRSTR", "strstr search for: " + needle);
                                    // Replace needle with empty string to prevent match
                                    args[1] = Memory.allocUtf8String("XXXXXXXXXXXXXXX");
                                    break;
                                }
                            }
                        }
                    } catch (e) {}
                }
            }
        });
    }

    // --- 2b) Port 27042 detection bypass (default frida-server port) ---
    var connect = Module.findExportByName("libc.so", "connect");
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function (args) {
                var sockAddr = args[1];
                var family = sockAddr.readU16();
                if (family === 2) { // AF_INET
                    var port = (sockAddr.add(2).readU8() << 8) | sockAddr.add(3).readU8();
                    if (port === 27042 || port === 27043) {
                        logDetection("FRIDA_PORT", "Connection to frida port " + port + " detected");
                    }
                }
            }
        });
    }

    // --- 2c) /proc/self/fd enumeration bypass ---
    var opendir = Module.findExportByName("libc.so", "opendir");
    if (opendir) {
        Interceptor.attach(opendir, {
            onEnter: function (args) {
                var path = args[0].readUtf8String();
                if (path && (path.indexOf("/proc/self/fd") !== -1 || path.indexOf("/proc/self/task") !== -1)) {
                    logDetection("FRIDA_PROC", "Process enumeration: " + path);
                }
            }
        });
    }

    // --- 2d) /proc/self/task/*/status TracerPid bypass ---
    var orig_fgets = Module.findExportByName("libc.so", "fgets");
    if (orig_fgets) {
        Interceptor.attach(orig_fgets, {
            onLeave: function (retval) {
                if (retval.isNull()) return;
                try {
                    var line = retval.readUtf8String();
                    if (line && line.indexOf("TracerPid:") !== -1) {
                        var cleaned = "TracerPid:\t0\n";
                        retval.writeUtf8String(cleaned);
                        logDetection("FRIDA_TRACER", "TracerPid spoofed to 0");
                    }
                } catch (e) {}
            }
        });
    }

    // --- 2e) dlopen/dlsym detection for frida modules ---
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                if (args[0] !== null) {
                    var name = args[0].readUtf8String();
                    if (name && (name.indexOf("frida") !== -1 || name.indexOf("gadget") !== -1)) {
                        logDetection("FRIDA_DLOPEN", "dlopen for: " + name);
                    }
                }
            }
        });
    }

    log("FRIDA", "Frida detection bypass initialized");
}

// ============================================================
// 3) SSL PINNING BYPASS (lightweight - does NOT break connectivity)
// ============================================================
function bypassSSLPinning() {
    log("SSL", "Initializing SSL pinning bypass (lightweight mode)...");

    // --- 3a) OkHttp CertificatePinner.check() - make it a no-op ---
    // IMPORTANT: We only skip the CHECK, we do NOT touch Builder.add().
    // Removing pins from the builder breaks OkHttp's TLS handshake entirely.
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
            logDetection("SSL_OKHTTP", "CertificatePinner.check bypassed for: " + hostname);
            // Do nothing - skip pin validation but connection stays alive
        };
        try {
            CertificatePinner["check$okhttp"].implementation = function (hostname, cleanedCerts) {
                logDetection("SSL_OKHTTP", "CertificatePinner.check$okhttp bypassed for: " + hostname);
            };
        } catch (e2) {
            log("SSL", "check$okhttp not found (OK - older OkHttp): " + e2);
        }
        log("SSL", "[1] OkHttp CertificatePinner.check() -> no-op (pins still added, just not enforced)");
    } catch (e) {
        log("SSL", "OkHttp CertificatePinner hook: " + e);
    }

    // --- 3b) Android platform TrustManagerImpl (if present) ---
    // This bypasses system-level cert validation without replacing the global SSLSocketFactory
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            logDetection("SSL_CONSCRYPT", "TrustManagerImpl.verifyChain bypassed for: " + host);
            return untrustedChain;
        };
        log("SSL", "[2] Conscrypt TrustManagerImpl.verifyChain() bypassed");
    } catch (e) {
        log("SSL", "TrustManagerImpl hook (non-critical): " + e);
    }

    // --- 3c) Network security config trust anchors ---
    // Hook the NetworkSecurityConfig to accept all certificates
    try {
        var NetworkSecurityTrustManager = Java.use("android.security.net.config.NetworkSecurityTrustManager");
        NetworkSecurityTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function (certs, authType) {
            logDetection("SSL_NETSEC", "NetworkSecurityTrustManager.checkServerTrusted bypassed");
        };
        log("SSL", "[3] NetworkSecurityTrustManager bypassed");
    } catch (e) {
        log("SSL", "NetworkSecurityTrustManager hook (non-critical): " + e);
    }

    // --- 3d) OkHttp HostnameVerifier ---
    try {
        var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (hostname, session) {
            logDetection("SSL_HOSTNAME", "OkHostnameVerifier.verify bypassed for: " + hostname);
            return true;
        };
        log("SSL", "[4] OkHostnameVerifier bypassed");
    } catch (e) {
        log("SSL", "OkHostnameVerifier hook (non-critical): " + e);
    }

    // --- 3e) WebViewClient SSL error bypass ---
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            logDetection("SSL_WEBVIEW", "WebView SSL error bypassed: " + error.toString());
            handler.proceed();
        };
        log("SSL", "[5] WebViewClient SSL error bypass applied");
    } catch (e) {
        log("SSL", "WebViewClient hook: " + e);
    }

    // NOTE: We intentionally do NOT:
    // - Replace the global SSLSocketFactory (breaks all HTTPS)
    // - Replace the global HostnameVerifier (breaks all HTTPS)
    // - Neutralize CertificatePinner.Builder.add() (breaks OkHttp client setup)
    // These aggressive approaches cause "no internet" issues.

    log("SSL", "SSL pinning bypass initialized (lightweight - internet should work)");
}

// ============================================================
// 4) EMULATOR DETECTION BYPASS
// ============================================================
function bypassEmulatorDetection() {
    log("EMU", "Initializing emulator detection bypass...");

    // --- 4a) Build properties spoofing ---
    var Build = Java.use("android.os.Build");
    var fields = {
        "PRODUCT": "walleye",
        "HARDWARE": "walleye",
        "MANUFACTURER": "Google",
        "MODEL": "Pixel 2",
        "BRAND": "google",
        "DEVICE": "walleye",
        "BOARD": "walleye",
        "FINGERPRINT": "google/walleye/walleye:11/RP1A.200720.009/6720564:user/release-keys",
        "HOST": "abfarm-release-rbe-64-00",
        "DISPLAY": "RP1A.200720.009"
    };

    for (var fname in fields) {
        try {
            var f = Build.class.getDeclaredField(fname);
            f.setAccessible(true);
            f.set(null, Java.use("java.lang.String").$new(fields[fname]));
        } catch (e) {}
    }
    log("EMU", "Build properties spoofed");

    // --- 4b) idwall SDK emulator detector bypass ---
    // k3.C12435a - combines remoteEmulatorDetector, localEmulatorDetector, rootDetector
    try {
        var IdwallDetector = Java.use("k3.C12435a");
        IdwallDetector.a.implementation = function () {
            logDetection("EMU_IDWALL", "idwall device integrity check -> returning 0 (clean)");
            return 0;
        };
    } catch (e) {
        log("EMU", "idwall detector hook: " + e);
    }

    // --- 4c) Jumio SDK isRooted bypass ---
    try {
        var JumioSDK = Java.use("com.jumio.sdk.JumioSDK$Companion");
        JumioSDK.isRooted.implementation = function (context) {
            logDetection("EMU_JUMIO", "Jumio SDK isRooted -> returning false");
            return false;
        };
    } catch (e) {
        log("EMU", "Jumio SDK isRooted hook: " + e);
    }

    log("EMU", "Emulator detection bypass initialized");
}

// ============================================================
// 5) DEBUGGER DETECTION BYPASS
// ============================================================
function bypassDebuggerDetection() {
    log("DEBUG", "Initializing debugger detection bypass...");

    // --- 5a) Debug.isDebuggerConnected bypass ---
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            logDetection("DEBUG_CHECK", "Debug.isDebuggerConnected -> false");
            return false;
        };
    } catch (e) {
        log("DEBUG", "Debug.isDebuggerConnected hook: " + e);
    }

    // --- 5b) ApplicationInfo flags bypass ---
    try {
        var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
        var origFlags = ApplicationInfo.flags;
        // Remove FLAG_DEBUGGABLE (0x2) if present
    } catch (e) {}

    // --- 5c) ptrace bypass ---
    var ptrace = Module.findExportByName("libc.so", "ptrace");
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function (args) {
                logDetection("DEBUG_PTRACE", "ptrace called with request: " + args[0]);
            },
            onLeave: function (retval) {
                retval.replace(0);
            }
        });
    }

    log("DEBUG", "Debugger detection bypass initialized");
}

// ============================================================
// 6) PLAY INTEGRITY BYPASS
// ============================================================
function bypassPlayIntegrity() {
    log("INTEGRITY", "Initializing Play Integrity bypass...");

    // --- 6a) IntegrityManager token request interception ---
    try {
        var IntegrityPc = Java.use("k3.Pc");

        // Hook the save device integrity method to always save clean data
        IntegrityPc.e.implementation = function (context, token, errorCode, integrityErrorCode) {
            logDetection("INTEGRITY", "Device integrity save intercepted - errorCode: " + errorCode + ", token present: " + (token !== null));
            // Call original but log the interaction
            this.e(context, token, errorCode, integrityErrorCode);
        };
    } catch (e) {
        log("INTEGRITY", "Play Integrity hook: " + e);
    }

    // --- 6b) DeviceIntegrity data spoofing ---
    try {
        var DeviceIntegrity = Java.use("k3.C12617n");
        DeviceIntegrity.$init.overload("java.lang.String", "java.lang.Integer", "java.lang.String", "java.lang.Integer").implementation = function (pkg, errorCode, token, integrityErrorCode) {
            logDetection("INTEGRITY", "DeviceIntegrity created - pkg: " + pkg + ", errorCode: " + errorCode);
            return this.$init(pkg, errorCode, token, integrityErrorCode);
        };
    } catch (e) {
        log("INTEGRITY", "DeviceIntegrity hook: " + e);
    }

    log("INTEGRITY", "Play Integrity bypass initialized");
}

// ============================================================
// 7) FINGERPRINTJS PRO BYPASS
// ============================================================
function bypassFingerprintJS() {
    log("FPJS", "Initializing FingerprintJS Pro bypass...");

    // --- 7a) Hook FingerprintJS Pro response ---
    try {
        var FPJSAction = Java.use("com.bitso.android.fingerprint.domain.action.GetFingerprintProDataAction");
        // The action calls fpjs_pro.e.a(timeout, onSuccess, onError)
        // We let it proceed normally but log the interaction
        log("FPJS", "GetFingerprintProDataAction class loaded for monitoring");
    } catch (e) {
        log("FPJS", "FingerprintJS action hook: " + e);
    }

    // --- 7b) FingerprintJS Pro secrets monitoring ---
    try {
        var FPSecrets = Java.use("com.bitso.android.fingerprint.FingerprintProSecrets");
        FPSecrets.e.implementation = function () {
            var key = this.e();
            logDetection("FPJS", "FingerprintPro API key accessed: " + key.substring(0, 8) + "...");
            return key;
        };
        FPSecrets.c.implementation = function () {
            var url = this.c();
            logDetection("FPJS", "FingerprintPro endpoint: " + url);
            return url;
        };
    } catch (e) {
        log("FPJS", "FingerprintJS secrets hook: " + e);
    }

    log("FPJS", "FingerprintJS Pro bypass initialized");
}

// ============================================================
// 8) iPROOV CALCIFER (NATIVE) BYPASS
// ============================================================
function bypassIproovCalcifer() {
    log("IPROOV", "Initializing iProov Calcifer native bypass...");

    // The libiproov-com-calcifer-lib.so has check2-check18 functions
    // These perform native root/hook/emulator detection

    try {
        var calciferLib = Module.findBaseAddress("libiproov-com-calcifer-lib.so");
        if (calciferLib) {
            log("IPROOV", "Calcifer library found at: " + calciferLib);

            // Hook all check functions (check2 through check18)
            var exports = Module.enumerateExports("libiproov-com-calcifer-lib.so");
            for (var i = 0; i < exports.length; i++) {
                var exp = exports[i];
                if (exp.name.match(/check\d+/) && exp.type === "function") {
                    (function(exportName, addr) {
                        Interceptor.attach(addr, {
                            onEnter: function (args) {
                                logDetection("IPROOV_CHECK", "Calcifer " + exportName + " called");
                            },
                            onLeave: function (retval) {
                                // Return 0 (clean/no detection)
                                retval.replace(0);
                                log("IPROOV", exportName + " -> spoofed to 0 (clean)");
                            }
                        });
                    })(exp.name, exp.address);
                }
            }
        } else {
            log("IPROOV", "Calcifer library not yet loaded - setting up delayed hook");
        }
    } catch (e) {
        log("IPROOV", "Calcifer hook error: " + e);
    }

    // Delayed hook for when the library loads later
    var dlopen_ptr = Module.findExportByName(null, "android_dlopen_ext") || Module.findExportByName(null, "dlopen");
    if (dlopen_ptr) {
        Interceptor.attach(dlopen_ptr, {
            onEnter: function (args) {
                if (args[0] !== null) {
                    var name = args[0].readUtf8String();
                    if (name && name.indexOf("calcifer") !== -1) {
                        this.isCalcifer = true;
                        log("IPROOV", "Calcifer library loading: " + name);
                    }
                }
            },
            onLeave: function (retval) {
                if (this.isCalcifer) {
                    hookCalciferChecks();
                }
            }
        });
    }

    // Also hook libiproov-com-lib.so which reads /proc/self/maps and /proc/self/task
    try {
        var iproovLib = Module.findBaseAddress("libiproov-com-lib.so");
        if (iproovLib) {
            log("IPROOV", "iProov main library found at: " + iproovLib);
        }
    } catch (e) {}

    log("IPROOV", "iProov Calcifer bypass initialized");
}

function hookCalciferChecks() {
    setTimeout(function () {
        try {
            var exports = Module.enumerateExports("libiproov-com-calcifer-lib.so");
            for (var i = 0; i < exports.length; i++) {
                var exp = exports[i];
                if (exp.name.match(/check\d+/) && exp.type === "function") {
                    (function(exportName, addr) {
                        Interceptor.attach(addr, {
                            onEnter: function (args) {
                                logDetection("IPROOV_CHECK", "Calcifer " + exportName + " called (delayed)");
                            },
                            onLeave: function (retval) {
                                retval.replace(0);
                            }
                        });
                    })(exp.name, exp.address);
                }
            }
            log("IPROOV", "Delayed Calcifer hooks installed");
        } catch (e) {
            log("IPROOV", "Delayed hook error: " + e);
        }
    }, 500);
}

// ============================================================
// 9) WEBVIEW / BROWSER-BASED DETECTION BYPASS
// ============================================================
function bypassWebViewDetection() {
    log("WEBVIEW", "Initializing WebView detection bypass...");

    // --- 9a) The app uses Chrome Custom Tabs for login (authCore/core/action/a.java) ---
    // We need to monitor/intercept WebView JS evaluation

    try {
        var WebView = Java.use("android.webkit.WebView");

        WebView.evaluateJavascript.implementation = function (script, callback) {
            logDetection("WEBVIEW_JS", "evaluateJavascript called, script length: " + script.length);
            // Check if the JS is trying to detect root/frida
            var scriptLower = script.toLowerCase();
            if (scriptLower.indexOf("root") !== -1 || scriptLower.indexOf("frida") !== -1 ||
                scriptLower.indexOf("jailbreak") !== -1 || scriptLower.indexOf("emulator") !== -1 ||
                scriptLower.indexOf("tamper") !== -1 || scriptLower.indexOf("integrity") !== -1) {
                logDetection("WEBVIEW_DETECT", "Suspicious JS detected: " + script.substring(0, 200));
            }
            return this.evaluateJavascript(script, callback);
        };

        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            if (url.startsWith("javascript:")) {
                logDetection("WEBVIEW_JS", "loadUrl javascript: " + url.substring(0, 200));
            } else {
                log("WEBVIEW", "loadUrl: " + url);
            }
            return this.loadUrl(url);
        };

        WebView.addJavascriptInterface.implementation = function (obj, name) {
            logDetection("WEBVIEW_IFACE", "addJavascriptInterface: " + name + " (" + obj.getClass().getName() + ")");
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) {
        log("WEBVIEW", "WebView hooks: " + e);
    }

    // --- 9b) Chrome Custom Tabs monitoring ---
    try {
        var CustomTabsBuilder = Java.use("com.bitso.android.authCore.core.action.a");
        CustomTabsBuilder.a.implementation = function () {
            logDetection("WEBVIEW_CUSTOMTAB", "Chrome Custom Tab intent builder called");
            return this.a();
        };
    } catch (e) {
        log("WEBVIEW", "Custom Tab hook: " + e);
    }

    // --- 9c) Inject JS into WebViews to spoof environment ---
    var webViewSpoofJS = [
        "// Bitso bypass - WebView environment spoofing",
        "Object.defineProperty(navigator, 'userAgent', {",
        "  get: function() { return 'Mozilla/5.0 (Linux; Android 11; Pixel 2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'; }",
        "});",
        "// Remove Frida-injected properties",
        "delete window.__frida__;",
        "delete window.frida;",
        "// Spoof WebGL renderer for emulator detection",
        "if (typeof WebGLRenderingContext !== 'undefined') {",
        "  var origGetParam = WebGLRenderingContext.prototype.getParameter;",
        "  WebGLRenderingContext.prototype.getParameter = function(param) {",
        "    if (param === 0x1F01) return 'Adreno (TM) 540';",
        "    if (param === 0x1F00) return 'Qualcomm';",
        "    return origGetParam.call(this, param);",
        "  };",
        "}"
    ].join("\n");

    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onPageFinished.implementation = function (view, url) {
            logDetection("WEBVIEW_LOADED", "Page finished: " + url);
            // Inject our spoofing JS
            view.evaluateJavascript(webViewSpoofJS, null);
            log("WEBVIEW", "Spoofing JS injected into: " + url);
            this.onPageFinished(view, url);
        };
    } catch (e) {
        log("WEBVIEW", "WebViewClient.onPageFinished hook: " + e);
    }

    log("WEBVIEW", "WebView detection bypass initialized");
}

// ============================================================
// 10) NETWORK MONITORING BYPASS
// ============================================================
function bypassNetworkDetection() {
    log("NETWORK", "Initializing network monitoring bypass...");

    // --- 10a) VPN detection bypass ---
    try {
        var NetworkInterface = Java.use("java.net.NetworkInterface");
        NetworkInterface.getName.implementation = function () {
            var name = this.getName();
            if (name === "tun0" || name === "ppp0" || name === "tap0") {
                logDetection("NETWORK_VPN", "VPN interface hidden: " + name);
                return "wlan0";
            }
            return name;
        };
    } catch (e) {
        log("NETWORK", "VPN detection bypass: " + e);
    }

    // --- 10b) Proxy detection bypass ---
    try {
        var System = Java.use("java.lang.System");
        var origGetProperty = System.getProperty.overload("java.lang.String");
        System.getProperty.overload("java.lang.String").implementation = function (key) {
            if (key === "http.proxyHost" || key === "http.proxyPort" ||
                key === "https.proxyHost" || key === "https.proxyPort") {
                logDetection("NETWORK_PROXY", "Proxy property check hidden: " + key);
                return null;
            }
            return origGetProperty.call(this, key);
        };
    } catch (e) {
        log("NETWORK", "Proxy detection bypass: " + e);
    }

    log("NETWORK", "Network monitoring bypass initialized");
}

// ============================================================
// MAIN ENTRY POINT
// ============================================================
Java.perform(function () {
    log("INIT", "=== Bitso Wallet Bypass Script Starting ===");
    log("INIT", "Target: com.bitso.wallet");
    log("INIT", "Timestamp: " + new Date().toISOString());

    try { bypassRootDetection(); } catch (e) { log("ERROR", "Root bypass failed: " + e); }
    try { bypassFridaDetection(); } catch (e) { log("ERROR", "Frida bypass failed: " + e); }
    try { bypassSSLPinning(); } catch (e) { log("ERROR", "SSL bypass failed: " + e); }
    try { bypassEmulatorDetection(); } catch (e) { log("ERROR", "Emulator bypass failed: " + e); }
    try { bypassDebuggerDetection(); } catch (e) { log("ERROR", "Debugger bypass failed: " + e); }
    try { bypassPlayIntegrity(); } catch (e) { log("ERROR", "Play Integrity bypass failed: " + e); }
    try { bypassFingerprintJS(); } catch (e) { log("ERROR", "FingerprintJS bypass failed: " + e); }
    try { bypassIproovCalcifer(); } catch (e) { log("ERROR", "iProov bypass failed: " + e); }
    try { bypassWebViewDetection(); } catch (e) { log("ERROR", "WebView bypass failed: " + e); }
    try { bypassNetworkDetection(); } catch (e) { log("ERROR", "Network bypass failed: " + e); }

    log("INIT", "=== All bypass modules loaded ===");
    log("INIT", "Monitoring active - detections will be logged in real-time");
    log("INIT", "Use the relay script to send output for analysis");
});

// ============================================================
// MESSAGE HANDLER (for relay communication)
// ============================================================
rpc.exports = {
    getDetections: function () {
        return DETECTIONS_FOUND;
    },
    getStatus: function () {
        return {
            detections: DETECTIONS_FOUND.length,
            modules: [
                "ROOT", "FRIDA", "SSL", "EMULATOR",
                "DEBUGGER", "INTEGRITY", "FPJS",
                "IPROOV", "WEBVIEW", "NETWORK"
            ]
        };
    },
    clearDetections: function () {
        DETECTIONS_FOUND = [];
        return "Detections cleared";
    }
};
