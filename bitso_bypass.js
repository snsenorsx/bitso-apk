/*
 * Bitso Wallet - Comprehensive Frida Bypass Script v3.0
 * =====================================================
 * Compatible with: Frida 17.x + Android 15 (Pixel 10 Pro XL)
 *
 * Fixes:
 *   - "Unable to find copied methods in java/lang/Thread" bug
 *   - /proc/self/maps Frida detection -> app self-kill
 *   - SSL pinning bypass that doesn't break internet
 *
 * Usage:
 *   frida -U -f com.bitso.wallet -l bitso_bypass.js
 *   frida -U -f com.bitso.wallet -l bitso_bypass.js 2>&1 | python3 frida_relay.py
 */

"use strict";

var VERSION = "3.0";
var DETECTIONS = [];
var ERRORS = [];
var hookStats = { installed: 0, failed: 0 };

// ============================================================
// LOGGING
// ============================================================
function log(cat, msg) {
    console.log("[*] [" + cat + "] " + msg);
}

function logTrigger(cat, msg) {
    console.log("[~] [TRIGGER] [" + cat + "] " + msg);
    DETECTIONS.push({ cat: cat, msg: msg, ts: Date.now() });
    send({ type: "detection", category: cat, message: msg });
}

function logErr(cat, msg) {
    console.log("[!] [ERROR] [" + cat + "] " + msg);
    ERRORS.push({ cat: cat, msg: msg });
}

function hookOk(id, desc) {
    hookStats.installed++;
    console.log("[+] [OK] [" + id + "] " + desc);
}

function hookFail(id, desc, err) {
    hookStats.failed++;
    console.log("[-] [FAIL] [" + id + "] " + desc + ": " + err);
}

// ============================================================
// PHASE 1: NATIVE HOOKS (run BEFORE Java VM - no Thread bug)
// These protect against /proc/self/maps scanning and app self-kill
// ============================================================
function installNativeHooks() {
    log("NATIVE", "=== Installing native-level protections ===");

    var libc = "libc.so";

    var fridaKeywords = [
        "frida", "gadget", "gum-js-loop", "gmain", "linjector",
        "frida-agent", "frida-server", "frida-gadget",
        "re.frida.server", "com.saurik.substrate"
    ];

    // --- N1) Block app self-termination ---
    // The app calls _exit() / exit() / kill() after detecting Frida in /proc/self/maps
    try {
        var _exit_ptr = Module.findExportByName(libc, "_exit");
        if (_exit_ptr) {
            Interceptor.replace(_exit_ptr, new NativeCallback(function (status) {
                logTrigger("ANTI-KILL", "_exit(" + status + ") BLOCKED - app tried to kill itself");
                // Don't actually exit
            }, "void", ["int"]));
            hookOk("N1a", "_exit() blocked");
        }
    } catch (e) { hookFail("N1a", "_exit block", e); }

    try {
        var exit_ptr = Module.findExportByName(libc, "exit");
        if (exit_ptr) {
            Interceptor.replace(exit_ptr, new NativeCallback(function (status) {
                logTrigger("ANTI-KILL", "exit(" + status + ") BLOCKED");
            }, "void", ["int"]));
            hookOk("N1b", "exit() blocked");
        }
    } catch (e) { hookFail("N1b", "exit block", e); }

    // Block kill(getpid(), signal) - app killing its own process
    try {
        var kill_ptr = Module.findExportByName(libc, "kill");
        var getpid_fn = new NativeFunction(Module.findExportByName(libc, "getpid"), "int", []);
        if (kill_ptr) {
            var orig_kill = new NativeFunction(kill_ptr, "int", ["int", "int"]);
            Interceptor.replace(kill_ptr, new NativeCallback(function (pid, sig) {
                var myPid = getpid_fn();
                if (pid === myPid) {
                    logTrigger("ANTI-KILL", "kill(self, " + sig + ") BLOCKED");
                    return 0;
                }
                return orig_kill(pid, sig);
            }, "int", ["int", "int"]));
            hookOk("N1c", "kill(self) blocked");
        }
    } catch (e) { hookFail("N1c", "kill block", e); }

    // Also block abort()
    try {
        var abort_ptr = Module.findExportByName(libc, "abort");
        if (abort_ptr) {
            Interceptor.replace(abort_ptr, new NativeCallback(function () {
                logTrigger("ANTI-KILL", "abort() BLOCKED");
            }, "void", []));
            hookOk("N1d", "abort() blocked");
        }
    } catch (e) { hookFail("N1d", "abort block", e); }

    // --- N2) /proc/self/maps filtering ---
    // Track which fds point to /proc/self/maps
    var mapsFds = {};

    try {
        var open_ptr = Module.findExportByName(libc, "open");
        if (open_ptr) {
            Interceptor.attach(open_ptr, {
                onEnter: function (args) {
                    try {
                        this.path = args[0].readUtf8String();
                    } catch (e) {
                        this.path = null;
                    }
                },
                onLeave: function (retval) {
                    if (this.path !== null && this.path.indexOf("/proc") !== -1 &&
                        this.path.indexOf("maps") !== -1) {
                        var fd = retval.toInt32();
                        if (fd >= 0) {
                            mapsFds[fd] = true;
                            logTrigger("MAPS", "/proc/*/maps opened (fd=" + fd + "): " + this.path);
                        }
                    }
                }
            });
            hookOk("N2a", "/proc/self/maps open() tracking");
        }
    } catch (e) { hookFail("N2a", "open tracking", e); }

    // Also track fopen
    try {
        var fopen_ptr = Module.findExportByName(libc, "fopen");
        if (fopen_ptr) {
            Interceptor.attach(fopen_ptr, {
                onEnter: function (args) {
                    try {
                        this.path = args[0].readUtf8String();
                    } catch (e) {
                        this.path = null;
                    }
                },
                onLeave: function (retval) {
                    if (this.path !== null && this.path.indexOf("/proc") !== -1 &&
                        this.path.indexOf("maps") !== -1 && !retval.isNull()) {
                        logTrigger("MAPS", "/proc/*/maps fopen: " + this.path);
                    }
                }
            });
            hookOk("N2a2", "/proc/self/maps fopen() tracking");
        }
    } catch (e) { hookFail("N2a2", "fopen tracking", e); }

    // Filter fgets output - hide frida entries from maps
    try {
        var fgets_ptr = Module.findExportByName(libc, "fgets");
        if (fgets_ptr) {
            Interceptor.attach(fgets_ptr, {
                onLeave: function (retval) {
                    if (retval.isNull()) return;
                    try {
                        var line = retval.readUtf8String();
                        if (line) {
                            var ll = line.toLowerCase();
                            // Filter frida entries
                            for (var i = 0; i < fridaKeywords.length; i++) {
                                if (ll.indexOf(fridaKeywords[i]) !== -1) {
                                    retval.writeUtf8String("00000000-00000000 ---p 00000000 00:00 0\n");
                                    logTrigger("MAPS-FILTER", "Filtered: " + line.trim().substring(0, 80));
                                    return;
                                }
                            }
                            // Spoof TracerPid
                            if (ll.indexOf("tracerpid:") !== -1 && ll.indexOf("tracerpid:\t0") === -1) {
                                retval.writeUtf8String("TracerPid:\t0\n");
                                logTrigger("TRACER", "TracerPid spoofed to 0");
                            }
                        }
                    } catch (e) {}
                }
            });
            hookOk("N2b", "fgets() maps/TracerPid filtering");
        }
    } catch (e) { hookFail("N2b", "fgets filtering", e); }

    // Filter read() for binary reads of maps
    try {
        var read_ptr = Module.findExportByName(libc, "read");
        if (read_ptr) {
            Interceptor.attach(read_ptr, {
                onEnter: function (args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    this.size = args[2].toInt32();
                },
                onLeave: function (retval) {
                    if (!mapsFds[this.fd]) return;
                    var bytesRead = retval.toInt32();
                    if (bytesRead <= 0) return;
                    try {
                        var content = this.buf.readUtf8String(bytesRead);
                        if (!content) return;
                        var lines = content.split("\n");
                        var filtered = [];
                        var removed = 0;
                        for (var i = 0; i < lines.length; i++) {
                            var ll = lines[i].toLowerCase();
                            var bad = false;
                            for (var j = 0; j < fridaKeywords.length; j++) {
                                if (ll.indexOf(fridaKeywords[j]) !== -1) {
                                    bad = true;
                                    removed++;
                                    break;
                                }
                            }
                            if (!bad) filtered.push(lines[i]);
                        }
                        if (removed > 0) {
                            var clean = filtered.join("\n");
                            this.buf.writeUtf8String(clean);
                            retval.replace(clean.length);
                            logTrigger("MAPS-FILTER", "read(): removed " + removed + " frida entries");
                        }
                    } catch (e) {}
                }
            });
            hookOk("N2c", "read() maps filtering");
        }
    } catch (e) { hookFail("N2c", "read filtering", e); }

    // Clean up mapsFds on close
    try {
        var close_ptr = Module.findExportByName(libc, "close");
        if (close_ptr) {
            Interceptor.attach(close_ptr, {
                onEnter: function (args) {
                    var fd = args[0].toInt32();
                    if (mapsFds[fd]) delete mapsFds[fd];
                }
            });
        }
    } catch (e) {}

    // --- N3) strstr bypass ---
    try {
        var strstr_ptr = Module.findExportByName(libc, "strstr");
        if (strstr_ptr) {
            Interceptor.attach(strstr_ptr, {
                onEnter: function (args) {
                    if (args[1].isNull()) return;
                    try {
                        var needle = args[1].readUtf8String();
                        if (needle) {
                            var nl = needle.toLowerCase();
                            for (var i = 0; i < fridaKeywords.length; i++) {
                                if (nl.indexOf(fridaKeywords[i]) !== -1) {
                                    this.shouldBlock = true;
                                    logTrigger("STRSTR", "strstr blocked: " + needle);
                                    break;
                                }
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.shouldBlock) {
                        retval.replace(ptr(0)); // NULL = not found
                    }
                }
            });
            hookOk("N3", "strstr() frida keyword blocking");
        }
    } catch (e) { hookFail("N3", "strstr", e); }

    // --- N4) __system_property_get ---
    try {
        var prop_get = Module.findExportByName(libc, "__system_property_get");
        if (prop_get) {
            Interceptor.attach(prop_get, {
                onEnter: function (args) {
                    this.name = args[0].readUtf8String();
                    this.valueBuf = args[1];
                },
                onLeave: function (retval) {
                    if (this.name === "ro.debuggable") {
                        this.valueBuf.writeUtf8String("0");
                    } else if (this.name === "ro.secure") {
                        this.valueBuf.writeUtf8String("1");
                    } else if (this.name === "ro.build.tags") {
                        this.valueBuf.writeUtf8String("release-keys");
                    } else if (this.name === "service.adb.root") {
                        this.valueBuf.writeUtf8String("0");
                    }
                }
            });
            hookOk("N4", "__system_property_get spoofing");
        }
    } catch (e) { hookFail("N4", "property spoofing", e); }

    // --- N5) ptrace ---
    try {
        var ptrace_ptr = Module.findExportByName(libc, "ptrace");
        if (ptrace_ptr) {
            Interceptor.replace(ptrace_ptr, new NativeCallback(function (req, pid, addr, data) {
                logTrigger("PTRACE", "ptrace(" + req + ") -> 0");
                return 0;
            }, "int", ["int", "int", "pointer", "pointer"]));
            hookOk("N5", "ptrace() -> 0");
        }
    } catch (e) { hookFail("N5", "ptrace", e); }

    // --- N6) access() for root files ---
    var nativeRootPaths = [
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
        "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
        "/su/bin/su", "/system/xbin/daemonsu", "/sbin/.magisk",
        "/data/adb/magisk", "/system/framework/XposedBridge.jar",
        "/cache/recovery/xposed.zip"
    ];
    try {
        var access_ptr = Module.findExportByName(libc, "access");
        if (access_ptr) {
            Interceptor.attach(access_ptr, {
                onEnter: function (args) {
                    try {
                        var p = args[0].readUtf8String();
                        if (p) {
                            for (var i = 0; i < nativeRootPaths.length; i++) {
                                if (p.indexOf(nativeRootPaths[i]) !== -1) {
                                    this.blockIt = true;
                                    logTrigger("ACCESS", "access() blocked: " + p);
                                    break;
                                }
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.blockIt) retval.replace(-1);
                }
            });
            hookOk("N6", "access() root path blocking");
        }
    } catch (e) { hookFail("N6", "access", e); }

    // --- N7) stat() for root files ---
    try {
        var stat_ptr = Module.findExportByName(libc, "stat");
        if (stat_ptr) {
            Interceptor.attach(stat_ptr, {
                onEnter: function (args) {
                    try {
                        var p = args[0].readUtf8String();
                        if (p) {
                            for (var i = 0; i < nativeRootPaths.length; i++) {
                                if (p.indexOf(nativeRootPaths[i]) !== -1) {
                                    this.blockIt = true;
                                    break;
                                }
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.blockIt) retval.replace(-1);
                }
            });
            hookOk("N7", "stat() root path blocking");
        }
    } catch (e) { hookFail("N7", "stat", e); }

    // --- N8) dlopen monitoring for security libs ---
    try {
        var dlopen_ptr = Module.findExportByName(null, "android_dlopen_ext") ||
                         Module.findExportByName(null, "dlopen");
        if (dlopen_ptr) {
            Interceptor.attach(dlopen_ptr, {
                onEnter: function (args) {
                    if (args[0] && !args[0].isNull()) {
                        try {
                            var name = args[0].readUtf8String();
                            if (name && (name.indexOf("calcifer") !== -1 || name.indexOf("iproov") !== -1)) {
                                logTrigger("DLOPEN", "Security lib: " + name);
                                this.secLib = name;
                            }
                        } catch (e) {}
                    }
                },
                onLeave: function (retval) {
                    if (this.secLib && this.secLib.indexOf("calcifer") !== -1) {
                        hookCalciferDelayed();
                    }
                }
            });
            hookOk("N8", "dlopen() security lib monitoring");
        }
    } catch (e) { hookFail("N8", "dlopen", e); }

    log("NATIVE", "=== Native hooks: " + hookStats.installed + " OK, " + hookStats.failed + " failed ===");
}

// ============================================================
// PHASE 2: JAVA HOOKS (delayed to avoid Thread bug on Android 15)
// ============================================================
function installJavaHooks() {

    // === ROOT DETECTION ===
    log("ROOT", "=== Bypassing root detection ===");

    var rootPaths = [
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
        "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
        "/su/bin/su", "/su/bin", "/system/xbin/daemonsu",
        "/sbin/.magisk", "/sbin/.magisk/modules", "/data/adb/magisk",
        "/data/magisk", "/magisk/.core/bin/",
        "/system/framework/XposedBridge.jar",
        "/cache/recovery/xposed.zip",
        "/data/adb/modules/riru_lsposed",
        "/sbin/.magisk/modules/riru_lsposed"
    ];

    // R1: File.exists
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) {
                    logTrigger("ROOT", "File.exists blocked: " + path);
                    return false;
                }
            }
            return this.exists();
        };
        hookOk("R1", "File.exists() (" + rootPaths.length + " paths)");
    } catch (e) { hookFail("R1", "File.exists", e); }

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
        "com.amphoras.hidemyroot", "com.formyhm.hideroot",
        "org.lsposed.manager", "moe.lsposed"
    ];

    // R2: PackageManager
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        var NNFE = Java.use("android.content.pm.PackageManager$NameNotFoundException");
        PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
            for (var i = 0; i < rootPackages.length; i++) {
                if (pkg === rootPackages[i]) {
                    logTrigger("ROOT", "getPackageInfo blocked: " + pkg);
                    throw NNFE.$new(pkg);
                }
            }
            return this.getPackageInfo(pkg, flags);
        };
        hookOk("R2", "PackageManager root blocking");
    } catch (e) { hookFail("R2", "PackageManager", e); }

    // R3: Runtime.exec
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if ((cmd.indexOf("/system/xbin/which") !== -1 && cmd.indexOf("su") !== -1) ||
                cmd === "su" || cmd.indexOf("/su ") !== -1) {
                logTrigger("ROOT", "Runtime.exec blocked: " + cmd);
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (arr) {
            var cmd = arr.join(" ");
            if (cmd === "su" || cmd.indexOf("/su") !== -1 ||
                (cmd.indexOf("which") !== -1 && cmd.indexOf("su") !== -1)) {
                logTrigger("ROOT", "Runtime.exec[] blocked: " + cmd);
                throw Java.use("java.io.IOException").$new("Permission denied");
            }
            return this.exec(arr);
        };
        hookOk("R3", "Runtime.exec su/which blocking");
    } catch (e) { hookFail("R3", "Runtime.exec", e); }

    // R4: Build.TAGS
    try {
        var Build = Java.use("android.os.Build");
        var f = Build.class.getDeclaredField("TAGS");
        f.setAccessible(true);
        f.set(null, Java.use("java.lang.String").$new("release-keys"));
        hookOk("R4", "Build.TAGS -> release-keys");
    } catch (e) { hookFail("R4", "Build.TAGS", e); }

    // R5: SystemProperties
    try {
        var SP = Java.use("android.os.SystemProperties");
        SP.get.overload("java.lang.String").implementation = function (key) {
            if (key === "ro.debuggable") return "0";
            if (key === "ro.secure") return "1";
            if (key === "ro.build.tags") return "release-keys";
            if (key === "service.adb.root") return "0";
            return this.get(key);
        };
        SP.get.overload("java.lang.String", "java.lang.String").implementation = function (key, def) {
            if (key === "ro.debuggable") return "0";
            if (key === "ro.secure") return "1";
            if (key === "ro.build.tags") return "release-keys";
            if (key === "service.adb.root") return "0";
            return this.get(key, def);
        };
        hookOk("R5", "SystemProperties spoofing");
    } catch (e) { hookFail("R5", "SystemProperties", e); }

    // R6: SplashActivity root check
    try {
        var SA = Java.use("com.bitso.wallet.onboarding.splash.SplashActivity");
        SA.B0.implementation = function (isRooted) {
            logTrigger("ROOT", "SplashActivity root check -> false");
            this.B0(false);
        };
        hookOk("R6", "SplashActivity.B0");
    } catch (e) { hookFail("R6", "SplashActivity", e); }

    // R7: Sentry root checker (try both obfuscated and non-obfuscated)
    try {
        var SR = Java.use("io.sentry.android.core.internal.util.RootChecker");
        SR.isDeviceRooted.implementation = function () {
            logTrigger("ROOT", "Sentry isDeviceRooted -> false");
            return false;
        };
        hookOk("R7", "Sentry RootChecker");
    } catch (e) {
        try {
            var SR2 = Java.use("io.sentry.android.core.internal.util.m");
            SR2.e.implementation = function () {
                logTrigger("ROOT", "Sentry root (obfuscated) -> false");
                return false;
            };
            hookOk("R7b", "Sentry root (obfuscated)");
        } catch (e2) { hookFail("R7", "Sentry", e2); }
    }

    // R8: SiftScience
    try {
        var Sift = Java.use("siftscience.android.DevicePropertiesCollector");
        try {
            Sift.existingRootFiles.implementation = function () {
                logTrigger("ROOT", "SiftScience rootFiles -> empty");
                return Java.use("java.util.ArrayList").$new();
            };
        } catch (e2) {}
        try {
            Sift.existingRootPackages.implementation = function () {
                logTrigger("ROOT", "SiftScience rootPackages -> empty");
                return Java.use("java.util.ArrayList").$new();
            };
        } catch (e2) {}
        try {
            Sift.existingDangerousProperties.implementation = function () {
                return Java.use("java.util.ArrayList").$new();
            };
        } catch (e2) {}
        try {
            Sift.existingRWPaths.implementation = function () {
                return Java.use("java.util.ArrayList").$new();
            };
        } catch (e2) {}
        hookOk("R8", "SiftScience root detection");
    } catch (e) { hookFail("R8", "SiftScience", e); }

    // R9: SharedPreferences root data source
    try {
        // Search for rooted device check data source classes
        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (name.indexOf("RootedDeviceCheckDataSource") !== -1) {
                    try {
                        var cls = Java.use(name);
                        var methods = cls.class.getDeclaredMethods();
                        for (var i = 0; i < methods.length; i++) {
                            var m = methods[i];
                            if (m.getReturnType().getName() === "boolean") {
                                var mName = m.getName();
                                cls[mName].implementation = function () {
                                    logTrigger("ROOT", "RootedDeviceCheckDataSource -> false");
                                    return false;
                                };
                                hookOk("R9", "SharedPref root check: " + name + "." + mName);
                                break;
                            }
                        }
                    } catch (e3) {}
                }
            },
            onComplete: function () {}
        });
    } catch (e) {}

    // === SSL PINNING (lightweight) ===
    log("SSL", "=== Bypassing SSL pinning (lightweight - internet stays working) ===");

    // S1: CertificatePinner.check -> no-op (DO NOT touch Builder.add)
    try {
        var CP = Java.use("okhttp3.CertificatePinner");
        CP.check.overload("java.lang.String", "java.util.List").implementation = function (host, certs) {
            logTrigger("SSL", "CertificatePinner.check bypassed: " + host);
        };
        try {
            CP["check$okhttp"].implementation = function (host, fn) {
                logTrigger("SSL", "CertificatePinner.check$okhttp bypassed: " + host);
            };
        } catch (e2) {}
        hookOk("S1", "OkHttp CertificatePinner.check -> no-op");
    } catch (e) { hookFail("S1", "CertificatePinner", e); }

    // S2: Conscrypt TrustManagerImpl
    try {
        var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMI.verifyChain.implementation = function (untrusted, anchors, host, clientAuth, ocsp, tlsSct) {
            logTrigger("SSL", "TrustManagerImpl.verifyChain bypassed: " + host);
            return untrusted;
        };
        hookOk("S2", "Conscrypt TrustManagerImpl");
    } catch (e) { hookFail("S2", "TrustManagerImpl", e); }

    // S3: NetworkSecurityTrustManager
    try {
        var NSTM = Java.use("android.security.net.config.NetworkSecurityTrustManager");
        NSTM.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function (certs, authType) {
            logTrigger("SSL", "NetworkSecurityTrustManager bypassed");
        };
        hookOk("S3", "NetworkSecurityTrustManager");
    } catch (e) { hookFail("S3", "NetworkSecurityTrustManager", e); }

    // S4: OkHostnameVerifier
    try {
        var OHV = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OHV.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (host, session) {
            logTrigger("SSL", "OkHostnameVerifier bypassed: " + host);
            return true;
        };
        hookOk("S4", "OkHostnameVerifier");
    } catch (e) { hookFail("S4", "OkHostnameVerifier", e); }

    // S5: WebViewClient SSL error
    try {
        var WVC = Java.use("android.webkit.WebViewClient");
        WVC.onReceivedSslError.implementation = function (view, handler, error) {
            logTrigger("SSL", "WebView SSL error bypassed");
            handler.proceed();
        };
        hookOk("S5", "WebViewClient SSL");
    } catch (e) { hookFail("S5", "WebViewClient", e); }

    // S6: HttpsURLConnection hostname verifier (lightweight - only intercept set, don't replace global)
    try {
        var HSURLC = Java.use("javax.net.ssl.HttpsURLConnection");
        HSURLC.setDefaultHostnameVerifier.implementation = function (verifier) {
            logTrigger("SSL", "HttpsURLConnection.setDefaultHostnameVerifier intercepted");
            // Let it through - don't block, just log
            this.setDefaultHostnameVerifier(verifier);
        };
        hookOk("S6", "HttpsURLConnection monitoring");
    } catch (e) { hookFail("S6", "HttpsURLConnection", e); }

    // === EMULATOR DETECTION ===
    log("EMU", "=== Bypassing emulator detection ===");

    try {
        var Build2 = Java.use("android.os.Build");
        var props = {
            "PRODUCT": "walleye", "HARDWARE": "walleye",
            "MANUFACTURER": "Google", "MODEL": "Pixel 2",
            "BRAND": "google", "DEVICE": "walleye", "BOARD": "walleye",
            "FINGERPRINT": "google/walleye/walleye:11/RP1A.200720.009/6720564:user/release-keys"
        };
        for (var k in props) {
            try {
                var ff = Build2.class.getDeclaredField(k);
                ff.setAccessible(true);
                ff.set(null, Java.use("java.lang.String").$new(props[k]));
            } catch (e2) {}
        }
        hookOk("E1", "Build properties spoofed");
    } catch (e) { hookFail("E1", "Build props", e); }

    // E2: Jumio
    try {
        var Jumio = Java.use("com.jumio.sdk.JumioSDK$Companion");
        Jumio.isRooted.implementation = function (ctx) {
            logTrigger("EMU", "Jumio isRooted -> false");
            return false;
        };
        hookOk("E2", "Jumio isRooted");
    } catch (e) { hookFail("E2", "Jumio", e); }

    // === DEBUGGER DETECTION ===
    log("DEBUG", "=== Bypassing debugger detection ===");

    try {
        var Dbg = Java.use("android.os.Debug");
        Dbg.isDebuggerConnected.implementation = function () { return false; };
        Dbg.waitingForDebugger.implementation = function () { return false; };
        hookOk("D1", "Debug.isDebuggerConnected + waitingForDebugger");
    } catch (e) { hookFail("D1", "Debug", e); }

    // === FRIDA DETECTION (Java) ===
    log("FRIDA", "=== Bypassing Frida detection (Java) ===");

    try {
        var CL = Java.use("java.lang.ClassLoader");
        CL.loadClass.overload("java.lang.String").implementation = function (name) {
            if (name === "de.robv.android.xposed.XposedBridge" ||
                name === "de.robv.android.xposed.XC_MethodHook" ||
                name === "com.saurik.substrate.MS") {
                logTrigger("FRIDA", "Xposed/Substrate class load blocked: " + name);
                throw Java.use("java.lang.ClassNotFoundException").$new(name);
            }
            return this.loadClass(name);
        };
        hookOk("F1", "Xposed/Substrate class blocking");
    } catch (e) { hookFail("F1", "ClassLoader", e); }

    // === PLAY INTEGRITY ===
    log("INTEGRITY", "=== Monitoring Play Integrity ===");

    try {
        var IntFactory = Java.use("com.google.android.play.core.integrity.IntegrityManagerFactory");
        IntFactory.create.implementation = function (ctx) {
            logTrigger("INTEGRITY", "IntegrityManagerFactory.create called");
            return this.create(ctx);
        };
        hookOk("I1", "IntegrityManagerFactory");
    } catch (e) { hookFail("I1", "IntegrityManagerFactory", e); }

    // === FINGERPRINT JS ===
    log("FPJS", "=== Monitoring FingerprintJS Pro ===");

    try {
        Java.use("com.bitso.android.fingerprint.domain.action.GetFingerprintProDataAction");
        hookOk("FP1", "FingerprintJS Pro class found");
    } catch (e) { hookFail("FP1", "FingerprintJS", e); }

    // === NETWORK ===
    log("NET", "=== Bypassing network detection ===");

    try {
        var NI = Java.use("java.net.NetworkInterface");
        NI.getName.implementation = function () {
            var name = this.getName();
            if (name === "tun0" || name === "ppp0" || name === "tap0") {
                logTrigger("NET", "VPN interface hidden: " + name);
                return "wlan0";
            }
            return name;
        };
        hookOk("NET1", "VPN interface hiding");
    } catch (e) { hookFail("NET1", "VPN", e); }

    try {
        var Sys = Java.use("java.lang.System");
        Sys.getProperty.overload("java.lang.String").implementation = function (key) {
            if (key === "http.proxyHost" || key === "http.proxyPort" ||
                key === "https.proxyHost" || key === "https.proxyPort") {
                logTrigger("NET", "Proxy property hidden: " + key);
                return null;
            }
            return this.getProperty(key);
        };
        hookOk("NET2", "Proxy detection bypass");
    } catch (e) { hookFail("NET2", "Proxy", e); }

    // === WEBVIEW ===
    log("WEBVIEW", "=== Monitoring WebView ===");

    try {
        var WV = Java.use("android.webkit.WebView");
        WV.evaluateJavascript.implementation = function (script, cb) {
            var sl = script.toLowerCase();
            if (sl.indexOf("root") !== -1 || sl.indexOf("frida") !== -1 ||
                sl.indexOf("jailbreak") !== -1 || sl.indexOf("tamper") !== -1) {
                logTrigger("WEBVIEW", "Suspicious JS: " + script.substring(0, 100));
            }
            return this.evaluateJavascript(script, cb);
        };
        hookOk("WV1", "WebView JS monitoring");
    } catch (e) { hookFail("WV1", "WebView", e); }

    log("JAVA", "=== Java hooks complete ===");
}

// ============================================================
// iProov Calcifer delayed hook
// ============================================================
function hookCalciferDelayed() {
    setTimeout(function () {
        try {
            var exports = Module.enumerateExports("libiproov-com-calcifer-lib.so");
            var hooked = 0;
            for (var i = 0; i < exports.length; i++) {
                var exp = exports[i];
                if (exp.name.match(/check\d+/) && exp.type === "function") {
                    (function (name, addr) {
                        Interceptor.attach(addr, {
                            onLeave: function (retval) {
                                retval.replace(0);
                                logTrigger("IPROOV", name + " -> 0");
                            }
                        });
                    })(exp.name, exp.address);
                    hooked++;
                }
            }
            if (hooked > 0) hookOk("CALC", "Calcifer " + hooked + " checks bypassed");
        } catch (e) {
            hookFail("CALC", "Calcifer", e);
        }
    }, 500);
}

// ============================================================
// CONSOLE COMMANDS
// ============================================================
function printStats() {
    console.log("\n=== BYPASS STATS ===");
    console.log("Hooks installed: " + hookStats.installed);
    console.log("Hooks failed:    " + hookStats.failed);
    console.log("Detections:      " + DETECTIONS.length);
    console.log("Errors:          " + ERRORS.length);
    console.log("====================\n");
}

function printTriggers() {
    console.log("\n=== TRIGGERED DETECTIONS ===");
    for (var i = 0; i < DETECTIONS.length; i++) {
        var d = DETECTIONS[i];
        console.log("[" + d.cat + "] " + d.msg);
    }
    console.log("Total: " + DETECTIONS.length);
    console.log("============================\n");
}

function printErrors() {
    console.log("\n=== ERRORS ===");
    for (var i = 0; i < ERRORS.length; i++) {
        var e = ERRORS[i];
        console.log("[" + e.cat + "] " + e.msg);
    }
    console.log("Total: " + ERRORS.length);
    console.log("===============\n");
}

// ============================================================
// MAIN - Two-phase startup to avoid Android 15 Thread bug
// ============================================================
console.log("==================================================");
console.log("[*] Bitso Bypass v" + VERSION + " - Android 15 Compatible");
console.log("[*] Phase 1: Native hooks (no Java VM)");
console.log("==================================================");

// PHASE 1: Native hooks - immediate, no Java.perform
installNativeHooks();

// PHASE 2: Java hooks - delayed 1.5s to let ART VM fully initialize
// This avoids "Unable to find copied methods in java/lang/Thread" bug
console.log("[*] Phase 2: Java hooks starting in 1.5s...");

setTimeout(function () {
    Java.perform(function () {
        try {
            installJavaHooks();
        } catch (e) {
            logErr("INIT", "Java hooks failed: " + e);
            console.log("[!] Retrying Java hooks in 3s...");
            setTimeout(function () {
                Java.perform(function () {
                    try {
                        installJavaHooks();
                    } catch (e2) {
                        logErr("INIT", "Java hooks RETRY failed: " + e2);
                        console.log("[!!!] Java hooks could not be installed.");
                        console.log("[!!!] Native-only protection is active.");
                    }
                });
            }, 3000);
        }
    });

    setTimeout(function () {
        console.log("\n==================================================");
        console.log("[*] Bitso Bypass v" + VERSION + " - READY");
        console.log("[*] Hooks: " + hookStats.installed + " OK, " + hookStats.failed + " failed");
        console.log("[*] Commands: printStats() printTriggers() printErrors()");
        console.log("==================================================\n");
    }, 3000);
}, 1500);

// RPC exports
rpc.exports = {
    getDetections: function () { return DETECTIONS; },
    getStatus: function () {
        return { hooks: hookStats, detections: DETECTIONS.length, errors: ERRORS.length };
    }
};
