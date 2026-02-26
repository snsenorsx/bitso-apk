/*
 * Bitso Wallet - Comprehensive Frida Bypass Script v3.1
 * =====================================================
 * Compatible with: Frida 17.x + Android 15 (Pixel 10 Pro XL)
 *
 * v3.1 fixes:
 *   - Native hooks: use null module (global search) instead of "libc.so"
 *   - Anti-kill: Memory.patchCode + Arm64Writer fallback for _exit/exit/abort
 *   - kill(self): Interceptor.attach + modify signal arg to 0
 *   - Removed ClassLoader.loadClass hook (causes ART GC crash)
 *   - Removed Java.enumerateLoadedClasses (causes ART GC crash)
 *   - Removed Build property spoofing (real device - not needed)
 *   - Increased Java hook delay to 3s for ART stability
 *
 * Usage:
 *   frida -U -f com.bitso.wallet -l bitso_bypass.js
 */

var VERSION = "3.1";
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
    try { send({ type: "detection", category: cat, message: msg }); } catch (e) {}
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

// Safe export finder - tries null (global search), then "libc.so"
function findExport(name) {
    try {
        var p = Module.findExportByName(null, name);
        if (p && !p.isNull()) return p;
    } catch (e) {}
    try {
        var p2 = Module.findExportByName("libc.so", name);
        if (p2 && !p2.isNull()) return p2;
    } catch (e) {}
    return null;
}

// ============================================================
// PHASE 1: NATIVE HOOKS (run BEFORE Java VM)
// ============================================================
function installNativeHooks() {
    log("NATIVE", "=== Installing native-level protections ===");

    // --- DIAGNOSTICS ---
    console.log("[DIAG] typeof Module: " + typeof Module);
    console.log("[DIAG] typeof Interceptor: " + typeof Interceptor);
    console.log("[DIAG] typeof NativeCallback: " + typeof NativeCallback);
    console.log("[DIAG] typeof NativeFunction: " + typeof NativeFunction);
    console.log("[DIAG] typeof Arm64Writer: " + typeof Arm64Writer);

    try {
        var libcMod = Process.findModuleByName("libc.so");
        console.log("[DIAG] libc module: " + (libcMod ? libcMod.path : "NOT FOUND"));
    } catch (e) {
        console.log("[DIAG] Process.findModuleByName error: " + e);
    }

    var testPtr = findExport("_exit");
    console.log("[DIAG] _exit ptr: " + testPtr);
    var testPtr2 = findExport("open");
    console.log("[DIAG] open ptr: " + testPtr2);

    var fridaKeywords = [
        "frida", "gadget", "gum-js-loop", "gmain", "linjector",
        "frida-agent", "frida-server", "frida-gadget",
        "re.frida.server", "com.saurik.substrate"
    ];

    // --- N1) Block app self-termination ---
    function patchWithRet(name, id) {
        var addr = findExport(name);
        if (!addr) {
            hookFail(id, name + " not found", "export not found");
            return;
        }

        // Try 1: Interceptor.replace with NativeCallback
        try {
            Interceptor.replace(addr, new NativeCallback(function () {
                logTrigger("ANTI-KILL", name + "() BLOCKED");
            }, "void", ["int"]));
            hookOk(id, name + "() blocked (replace)");
            return;
        } catch (e1) {
            console.log("[DIAG] " + name + " replace failed: " + e1);
        }

        // Try 2: Memory.patchCode with ARM64 RET instruction
        try {
            Memory.patchCode(addr, 4, function (code) {
                var w = new Arm64Writer(code, { pc: addr });
                w.putRet();
                w.flush();
            });
            hookOk(id, name + "() blocked (ARM64 RET patch)");
            return;
        } catch (e2) {
            console.log("[DIAG] " + name + " patchCode failed: " + e2);
        }

        // Try 3: Interceptor.attach for logging only
        try {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    logTrigger("ANTI-KILL", name + "(" + args[0] + ") called (NOT blocked)");
                }
            });
            hookOk(id, name + "() monitored (attach only)");
        } catch (e3) {
            hookFail(id, name, e3);
        }
    }

    patchWithRet("_exit", "N1a");
    patchWithRet("exit", "N1b");
    patchWithRet("abort", "N1d");

    // kill(self) - modify signal arg to 0 via Interceptor.attach
    try {
        var kill_ptr = findExport("kill");
        var getpid_ptr = findExport("getpid");
        if (kill_ptr && getpid_ptr) {
            var getpid_fn = new NativeFunction(getpid_ptr, "int", []);
            Interceptor.attach(kill_ptr, {
                onEnter: function (args) {
                    var pid = args[0].toInt32();
                    var sig = args[1].toInt32();
                    if (pid === getpid_fn() && sig !== 0) {
                        logTrigger("ANTI-KILL", "kill(self, " + sig + ") -> kill(self, 0)");
                        args[1] = ptr(0);
                    }
                }
            });
            hookOk("N1c", "kill(self) signal neutralized");
        } else {
            hookFail("N1c", "kill", "export not found");
        }
    } catch (e) { hookFail("N1c", "kill", e); }

    // --- N2) /proc/self/maps filtering ---
    var mapsFds = {};

    try {
        var open_ptr = findExport("open");
        if (open_ptr) {
            Interceptor.attach(open_ptr, {
                onEnter: function (args) {
                    try { this.path = args[0].readUtf8String(); } catch (e) { this.path = null; }
                },
                onLeave: function (retval) {
                    if (this.path && this.path.indexOf("/proc") !== -1 && this.path.indexOf("maps") !== -1) {
                        var fd = retval.toInt32();
                        if (fd >= 0) {
                            mapsFds[fd] = true;
                            logTrigger("MAPS", "open('" + this.path + "') fd=" + fd);
                        }
                    }
                }
            });
            hookOk("N2a", "open() /proc/maps tracking");
        }
    } catch (e) { hookFail("N2a", "open tracking", e); }

    try {
        var fopen_ptr = findExport("fopen");
        if (fopen_ptr) {
            Interceptor.attach(fopen_ptr, {
                onEnter: function (args) {
                    try { this.path = args[0].readUtf8String(); } catch (e) { this.path = null; }
                },
                onLeave: function (retval) {
                    if (this.path && this.path.indexOf("/proc") !== -1 && this.path.indexOf("maps") !== -1 && !retval.isNull()) {
                        logTrigger("MAPS", "fopen('" + this.path + "')");
                    }
                }
            });
            hookOk("N2a2", "fopen() /proc/maps tracking");
        }
    } catch (e) { hookFail("N2a2", "fopen tracking", e); }

    try {
        var fgets_ptr = findExport("fgets");
        if (fgets_ptr) {
            Interceptor.attach(fgets_ptr, {
                onLeave: function (retval) {
                    if (retval.isNull()) return;
                    try {
                        var line = retval.readUtf8String();
                        if (line) {
                            var ll = line.toLowerCase();
                            for (var i = 0; i < fridaKeywords.length; i++) {
                                if (ll.indexOf(fridaKeywords[i]) !== -1) {
                                    retval.writeUtf8String("00000000-00000000 ---p 00000000 00:00 0\n");
                                    logTrigger("MAPS-FILTER", "fgets filtered: " + line.trim().substring(0, 60));
                                    return;
                                }
                            }
                            if (ll.indexOf("tracerpid:") !== -1 && ll.indexOf("tracerpid:\t0") === -1) {
                                retval.writeUtf8String("TracerPid:\t0\n");
                                logTrigger("TRACER", "TracerPid -> 0");
                            }
                        }
                    } catch (e) {}
                }
            });
            hookOk("N2b", "fgets() frida/TracerPid filtering");
        }
    } catch (e) { hookFail("N2b", "fgets", e); }

    try {
        var read_ptr = findExport("read");
        if (read_ptr) {
            Interceptor.attach(read_ptr, {
                onEnter: function (args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    this.sz = args[2].toInt32();
                },
                onLeave: function (retval) {
                    if (!mapsFds[this.fd]) return;
                    var n = retval.toInt32();
                    if (n <= 0) return;
                    try {
                        var content = this.buf.readUtf8String(n);
                        if (!content) return;
                        var lines = content.split("\n");
                        var filtered = [];
                        var removed = 0;
                        for (var i = 0; i < lines.length; i++) {
                            var ll = lines[i].toLowerCase();
                            var bad = false;
                            for (var j = 0; j < fridaKeywords.length; j++) {
                                if (ll.indexOf(fridaKeywords[j]) !== -1) { bad = true; removed++; break; }
                            }
                            if (!bad) filtered.push(lines[i]);
                        }
                        if (removed > 0) {
                            var clean = filtered.join("\n");
                            this.buf.writeUtf8String(clean);
                            retval.replace(clean.length);
                            logTrigger("MAPS-FILTER", "read() removed " + removed + " frida entries");
                        }
                    } catch (e) {}
                }
            });
            hookOk("N2c", "read() maps filtering");
        }
    } catch (e) { hookFail("N2c", "read", e); }

    try {
        var close_ptr = findExport("close");
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
        var strstr_ptr = findExport("strstr");
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
                                    break;
                                }
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.shouldBlock) {
                        retval.replace(ptr(0));
                    }
                }
            });
            hookOk("N3", "strstr() frida keyword blocking");
        }
    } catch (e) { hookFail("N3", "strstr", e); }

    // --- N4) __system_property_get ---
    try {
        var prop_get = findExport("__system_property_get");
        if (prop_get) {
            Interceptor.attach(prop_get, {
                onEnter: function (args) {
                    try { this.propName = args[0].readUtf8String(); } catch (e) { this.propName = null; }
                    this.valueBuf = args[1];
                },
                onLeave: function (retval) {
                    if (this.propName === "ro.debuggable") this.valueBuf.writeUtf8String("0");
                    else if (this.propName === "ro.secure") this.valueBuf.writeUtf8String("1");
                    else if (this.propName === "ro.build.tags") this.valueBuf.writeUtf8String("release-keys");
                    else if (this.propName === "service.adb.root") this.valueBuf.writeUtf8String("0");
                }
            });
            hookOk("N4", "__system_property_get spoofing");
        }
    } catch (e) { hookFail("N4", "property_get", e); }

    // --- N5) ptrace ---
    try {
        var ptrace_ptr = findExport("ptrace");
        if (ptrace_ptr) {
            Interceptor.attach(ptrace_ptr, {
                onEnter: function (args) {
                    this.req = args[0].toInt32();
                },
                onLeave: function (retval) {
                    retval.replace(0);
                    logTrigger("PTRACE", "ptrace(" + this.req + ") -> 0");
                }
            });
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
        var access_ptr = findExport("access");
        if (access_ptr) {
            Interceptor.attach(access_ptr, {
                onEnter: function (args) {
                    try {
                        var p = args[0].readUtf8String();
                        if (p) {
                            for (var i = 0; i < nativeRootPaths.length; i++) {
                                if (p === nativeRootPaths[i]) { this.blockIt = true; break; }
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
        var stat_ptr = findExport("stat");
        if (stat_ptr) {
            Interceptor.attach(stat_ptr, {
                onEnter: function (args) {
                    try {
                        var p = args[0].readUtf8String();
                        if (p) {
                            for (var i = 0; i < nativeRootPaths.length; i++) {
                                if (p === nativeRootPaths[i]) { this.blockIt = true; break; }
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

    // --- N8) dlopen monitoring ---
    try {
        var dlopen_ptr = findExport("android_dlopen_ext");
        if (!dlopen_ptr) dlopen_ptr = findExport("dlopen");
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
// NOTE: ClassLoader.loadClass hook REMOVED - causes ART GC crash
// NOTE: Java.enumerateLoadedClasses REMOVED - causes ART GC crash
// ============================================================
function installJavaHooks() {

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

    // R1: File.exists - with recursion guard
    try {
        var File = Java.use("java.io.File");
        var _existsGuard = false;
        File.exists.implementation = function () {
            if (_existsGuard) return this.exists();
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) {
                    logTrigger("ROOT", "File.exists blocked: " + path);
                    return false;
                }
            }
            _existsGuard = true;
            try {
                return this.exists();
            } finally {
                _existsGuard = false;
            }
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

    // R7: Sentry root checker
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

    // === SSL PINNING (lightweight) ===
    log("SSL", "=== Bypassing SSL pinning (lightweight - internet stays working) ===");

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

    try {
        var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMI.verifyChain.implementation = function (untrusted, anchors, host, clientAuth, ocsp, tlsSct) {
            logTrigger("SSL", "TrustManagerImpl.verifyChain bypassed: " + host);
            return untrusted;
        };
        hookOk("S2", "Conscrypt TrustManagerImpl");
    } catch (e) { hookFail("S2", "TrustManagerImpl", e); }

    try {
        var NSTM = Java.use("android.security.net.config.NetworkSecurityTrustManager");
        NSTM.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function (certs, authType) {
            logTrigger("SSL", "NetworkSecurityTrustManager bypassed");
        };
        hookOk("S3", "NetworkSecurityTrustManager");
    } catch (e) { hookFail("S3", "NetworkSecurityTrustManager", e); }

    try {
        var OHV = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OHV.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (host, session) {
            logTrigger("SSL", "OkHostnameVerifier bypassed: " + host);
            return true;
        };
        hookOk("S4", "OkHostnameVerifier");
    } catch (e) { hookFail("S4", "OkHostnameVerifier", e); }

    try {
        var WVC = Java.use("android.webkit.WebViewClient");
        WVC.onReceivedSslError.implementation = function (view, handler, error) {
            logTrigger("SSL", "WebView SSL error bypassed");
            handler.proceed();
        };
        hookOk("S5", "WebViewClient SSL");
    } catch (e) { hookFail("S5", "WebViewClient", e); }

    try {
        var HSURLC = Java.use("javax.net.ssl.HttpsURLConnection");
        HSURLC.setDefaultHostnameVerifier.implementation = function (verifier) {
            logTrigger("SSL", "HttpsURLConnection.setDefaultHostnameVerifier intercepted");
            this.setDefaultHostnameVerifier(verifier);
        };
        hookOk("S6", "HttpsURLConnection monitoring");
    } catch (e) { hookFail("S6", "HttpsURLConnection", e); }

    // === EMULATOR DETECTION ===
    log("EMU", "=== Bypassing emulator detection ===");

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
    // ClassLoader.loadClass hook REMOVED - causes ART GC crash on Android 15
    log("FRIDA", "=== Frida detection handled by native hooks ===");
    hookOk("F-NOTE", "Native strstr + maps filtering active");

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
// MAIN - Two-phase startup
// ============================================================
console.log("==================================================");
console.log("[*] Bitso Bypass v" + VERSION + " - Android 15 Compatible");
console.log("[*] Phase 1: Native hooks (no Java VM)");
console.log("==================================================");

// PHASE 1: Native hooks - immediate, no Java.perform
installNativeHooks();

// PHASE 2: Java hooks - delayed 3s to let ART VM fully initialize
console.log("[*] Phase 2: Java hooks starting in 3s...");

setTimeout(function () {
    Java.perform(function () {
        try {
            installJavaHooks();
        } catch (e) {
            logErr("INIT", "Java hooks failed: " + e);
            console.log("[!] Retrying Java hooks in 5s...");
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
            }, 5000);
        }
    });

    setTimeout(function () {
        console.log("\n==================================================");
        console.log("[*] Bitso Bypass v" + VERSION + " - READY");
        console.log("[*] Hooks: " + hookStats.installed + " OK, " + hookStats.failed + " failed");
        console.log("[*] Commands: printStats() printTriggers() printErrors()");
        console.log("==================================================\n");
    }, 5000);
}, 3000);

// RPC exports
rpc.exports = {
    getDetections: function () { return DETECTIONS; },
    getStatus: function () {
        return { hooks: hookStats, detections: DETECTIONS.length, errors: ERRORS.length };
    }
};
