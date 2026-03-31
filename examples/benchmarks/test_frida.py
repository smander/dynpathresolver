#!/usr/bin/env python3
"""Test Frida instrumentation for dynamic validation."""

import frida
import os
import time
import sys

def test_frida_dlopen():
    """Test Frida hooking of dlopen."""
    binary = "/app/examples/benchmarks/01_simple_dlopen/test_binary"
    binary_dir = os.path.dirname(binary)

    print(f"Frida version: {frida.__version__}")
    print(f"Binary: {binary}")
    print(f"Binary exists: {os.path.exists(binary)}")

    try:
        # Spawn the process
        pid = frida.spawn([binary], cwd=binary_dir)
        print(f"Spawned process with PID: {pid}")

        # Attach to the process
        session = frida.attach(pid)
        print("Attached to process")

        # Frida script to hook dlopen using multiple approaches
        script_code = '''
send({type: "info", msg: "Script starting"});

var dlopen_hooked = false;

// Approach 1: Try enumerateSymbols (includes both exports and imports)
Process.enumerateModules().forEach(function(mod) {
    if (dlopen_hooked) return;

    if (mod.name.indexOf("libc") !== -1 ||
        mod.name.indexOf("libdl") !== -1 ||
        mod.name.indexOf("ld-linux") !== -1) {

        send({type: "checking_module", name: mod.name});

        // Try enumerateSymbols
        try {
            mod.enumerateSymbols().forEach(function(sym) {
                if (dlopen_hooked) return;
                if (sym.name === "dlopen" || sym.name === "__libc_dlopen_mode") {
                    send({type: "found_symbol", name: sym.name, address: sym.address.toString(), type: sym.type});
                    if (!sym.address.isNull()) {
                        try {
                            Interceptor.attach(sym.address, {
                                onEnter: function(args) {
                                    var path = args[0] ? args[0].readCString() : "(null)";
                                    send({type: "dlopen_called", path: path});
                                }
                            });
                            send({type: "hook_success", name: sym.name});
                            dlopen_hooked = true;
                        } catch(e) {
                            send({type: "hook_error", error: e.toString()});
                        }
                    }
                }
            });
        } catch(e) {
            send({type: "symbols_error", module: mod.name, error: e.toString()});
        }

        // Also try enumerateExports
        if (!dlopen_hooked) {
            try {
                mod.enumerateExports().forEach(function(exp) {
                    if (dlopen_hooked) return;
                    if (exp.name === "dlopen") {
                        send({type: "found_export", name: exp.name, address: exp.address.toString()});
                        if (!exp.address.isNull()) {
                            Interceptor.attach(exp.address, {
                                onEnter: function(args) {
                                    send({type: "dlopen_called", path: args[0].readCString()});
                                }
                            });
                            dlopen_hooked = true;
                            send({type: "hook_success", name: exp.name});
                        }
                    }
                });
            } catch(e) {}
        }
    }
});

// Approach 2: Try using DebugSymbol.fromName
if (!dlopen_hooked) {
    send({type: "trying_debug_symbol"});
    try {
        var addr = DebugSymbol.fromName("dlopen").address;
        if (addr && !addr.isNull()) {
            send({type: "debug_symbol_found", address: addr.toString()});
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    send({type: "dlopen_called", path: args[0].readCString()});
                }
            });
            dlopen_hooked = true;
            send({type: "hook_success", method: "DebugSymbol"});
        }
    } catch(e) {
        send({type: "debug_symbol_error", error: e.toString()});
    }
}

// Approach 3: Try using the slot (GOT entry) to read the real dlopen address
if (!dlopen_hooked) {
    send({type: "trying_plt_scan"});
    var main_module = Process.enumerateModules()[0];
    try {
        main_module.enumerateImports().forEach(function(imp) {
            if (dlopen_hooked) return;
            if (imp.name === "dlopen") {
                send({type: "found_import", name: imp.name, address: imp.address ? imp.address.toString() : "null", slot: imp.slot ? imp.slot.toString() : "null"});

                // Try to read the actual function address from the GOT slot
                if (imp.slot) {
                    try {
                        var real_addr = imp.slot.readPointer();
                        send({type: "got_real_addr", real_address: real_addr.toString()});

                        if (!real_addr.isNull() && real_addr.compare(imp.address) !== 0) {
                            Interceptor.attach(real_addr, {
                                onEnter: function(args) {
                                    send({type: "dlopen_called", path: args[0].readCString()});
                                }
                            });
                            dlopen_hooked = true;
                            send({type: "hook_success", method: "GOT_deref"});
                        }
                    } catch(e) {
                        send({type: "got_read_error", error: e.toString()});
                    }
                }

                // Fallback: try Interceptor.replace to wrap the PLT
                if (!dlopen_hooked && imp.address) {
                    try {
                        var orig_dlopen = new NativeFunction(imp.address, 'pointer', ['pointer', 'int']);
                        Interceptor.replace(imp.address, new NativeCallback(function(path, flags) {
                            var path_str = path ? path.readCString() : "(null)";
                            send({type: "dlopen_called", path: path_str, flags: flags});
                            return orig_dlopen(path, flags);
                        }, 'pointer', ['pointer', 'int']));
                        dlopen_hooked = true;
                        send({type: "hook_success", method: "replace"});
                    } catch(e) {
                        send({type: "replace_error", error: e.toString()});
                    }
                }
            }
        });
    } catch(e) {
        send({type: "import_error", error: e.toString()});
    }
}

// Approach 4: Hook _dl_open in ld-linux (the actual implementation)
if (!dlopen_hooked) {
    send({type: "trying_dl_open"});
    Process.enumerateModules().forEach(function(mod) {
        if (dlopen_hooked) return;
        if (mod.name.indexOf("ld-linux") !== -1) {
            try {
                mod.enumerateSymbols().forEach(function(sym) {
                    if (dlopen_hooked) return;
                    if (sym.name === "_dl_open" || sym.name === "__libc_dlopen_mode" || sym.name === "_dl_catch_error") {
                        send({type: "found_ld_symbol", name: sym.name, address: sym.address.toString()});
                        if (sym.name === "_dl_open" && !sym.address.isNull()) {
                            try {
                                Interceptor.attach(sym.address, {
                                    onEnter: function(args) {
                                        // _dl_open(const char *file, int mode, ...)
                                        var path = args[0] ? args[0].readCString() : "(null)";
                                        send({type: "dlopen_called", path: path, via: "_dl_open"});
                                    }
                                });
                                dlopen_hooked = true;
                                send({type: "hook_success", method: "_dl_open"});
                            } catch(e) {
                                send({type: "dl_open_hook_error", error: e.toString()});
                            }
                        }
                    }
                });
            } catch(e) {
                send({type: "ld_symbols_error", error: e.toString()});
            }
        }
    });
}

// Approach 5: Try hooking in libdl.so.2 directly
if (!dlopen_hooked) {
    send({type: "trying_libdl_direct"});
    Process.enumerateModules().forEach(function(mod) {
        if (dlopen_hooked) return;
        if (mod.name === "libdl.so.2") {
            send({type: "scanning_libdl", base: mod.base.toString(), size: mod.size});
            try {
                mod.enumerateSymbols().forEach(function(sym) {
                    send({type: "libdl_symbol", name: sym.name, type: sym.type});
                    if (sym.name === "dlopen" && sym.type === "function") {
                        send({type: "found_libdl_dlopen", address: sym.address.toString()});
                        try {
                            Interceptor.attach(sym.address, {
                                onEnter: function(args) {
                                    send({type: "dlopen_called", path: args[0].readCString()});
                                }
                            });
                            dlopen_hooked = true;
                            send({type: "hook_success", method: "libdl_symbol"});
                        } catch(e) {
                            send({type: "libdl_hook_error", error: e.toString()});
                        }
                    }
                });
            } catch(e) {
                send({type: "libdl_error", error: e.toString()});
            }
        }
    });
}

// Approach 6: Calculate dlopen address from libc base + known offset
if (!dlopen_hooked) {
    send({type: "trying_libc_offset"});
    Process.enumerateModules().forEach(function(mod) {
        if (dlopen_hooked) return;
        if (mod.name.indexOf("libc") !== -1 && mod.name.indexOf(".so") !== -1) {
            // dlopen is at offset 0x820e0 in libc.so.6 (from readelf)
            var dlopen_offset = 0x820e0;
            var dlopen_addr = mod.base.add(dlopen_offset);
            send({type: "calculated_dlopen", base: mod.base.toString(), offset: dlopen_offset.toString(16), address: dlopen_addr.toString()});

            try {
                Interceptor.attach(dlopen_addr, {
                    onEnter: function(args) {
                        var path = args[0] ? args[0].readCString() : "(null)";
                        send({type: "dlopen_called", path: path, via: "libc_offset"});
                    }
                });
                dlopen_hooked = true;
                send({type: "hook_success", method: "libc_offset"});
            } catch(e) {
                send({type: "libc_offset_error", error: e.toString()});
            }
        }
    });
}

send({type: "setup_complete", dlopen_hooked: dlopen_hooked});
'''

        script = session.create_script(script_code)

        messages = []
        dlopen_calls = []

        def on_message(message, data):
            messages.append(message)
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if payload.get("type") == "dlopen_called":
                    dlopen_calls.append(payload.get("path"))
                    print(f"  [DLOPEN] {payload.get('path')}")

        script.on("message", on_message)
        script.load()
        print("Script loaded")

        # Resume the process
        frida.resume(pid)
        print("Process resumed, waiting for execution...")

        # Wait for process to complete
        time.sleep(3)

        print(f"\n{'='*60}")
        print("RESULTS")
        print(f"{'='*60}")
        print(f"Total messages: {len(messages)}")
        print(f"dlopen calls detected: {len(dlopen_calls)}")

        print("\nAll messages:")
        for m in messages:
            if m.get("type") == "send":
                print(f"  {m.get('payload')}")
            elif m.get("type") == "error":
                print(f"  ERROR: {m}")

        if dlopen_calls:
            print(f"\n*** SUCCESS: Frida detected dlopen calls: {dlopen_calls}")
            return True
        else:
            print("\n*** WARNING: No dlopen calls detected")
            return False

    except Exception as e:
        print(f"Frida error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_frida_dlopen()
    sys.exit(0 if success else 1)
