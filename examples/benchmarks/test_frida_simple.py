#!/usr/bin/env python3
"""Simple Frida test on first benchmark with detailed debugging."""

import os
import sys
import time
import frida

sys.path.insert(0, '/app')

def test_single_benchmark():
    """Test Frida on 01_simple_dlopen."""
    binary = "/app/examples/benchmarks/01_simple_dlopen/test_binary"
    binary_dir = os.path.dirname(binary)
    expected_lib = "./libplugin.so"

    print(f"Testing: {binary}")
    print(f"Working dir: {binary_dir}")
    print(f"Expected: {expected_lib}")
    print()

    # Simple Frida script with libc offset method
    script_code = '''
var hooked = false;
send({type: "info", msg: "Script starting"});

// Method: libc offset (works in Docker)
Process.enumerateModules().forEach(function(mod) {
    if (hooked) return;
    if (mod.name.indexOf("libc") !== -1 && mod.name.indexOf(".so") !== -1) {
        send({type: "info", msg: "Found libc: " + mod.name + " at " + mod.base.toString()});
        var offsets = [0x820e0, 0x81fe0, 0x82000, 0x80000];
        for (var k = 0; k < offsets.length && !hooked; k++) {
            try {
                var dlopen_addr = mod.base.add(offsets[k]);
                Interceptor.attach(dlopen_addr, {
                    onEnter: function(args) {
                        var path = args[0] ? args[0].readCString() : "(null)";
                        send({type: "dlopen", path: path});
                    }
                });
                send({type: "info", msg: "Hooked dlopen at offset 0x" + offsets[k].toString(16)});
                hooked = true;
            } catch (e) {
                send({type: "debug", msg: "Failed offset 0x" + offsets[k].toString(16) + ": " + e.toString()});
            }
        }
    }
});

send({type: "info", msg: "Script setup complete, hooked=" + hooked});
'''

    dlopen_calls = []

    def on_message(message, data):
        if message['type'] == 'send':
            payload = message['payload']
            print(f"  MSG: {payload}")
            if payload.get('type') == 'dlopen':
                dlopen_calls.append(payload.get('path'))
        elif message['type'] == 'error':
            print(f"  ERR: {message}")

    try:
        print("Spawning process...")
        pid = frida.spawn([binary], cwd=binary_dir, stdio='pipe')
        print(f"PID: {pid}")

        print("Attaching...")
        session = frida.attach(pid)
        print(f"Session created, detached={session.is_detached}")

        print("Creating script...")
        script = session.create_script(script_code)
        script.on('message', on_message)

        print("Loading script...")
        script.load()

        print("Resuming process...")
        frida.resume(pid)

        # Simple wait - just a fixed time
        print("Waiting 2 seconds for execution...")
        time.sleep(2)

        print(f"\nSession detached: {session.is_detached}")
        print(f"dlopen calls captured: {dlopen_calls}")

        # Cleanup
        try:
            session.detach()
        except:
            pass
        try:
            frida.kill(pid)
        except:
            pass

        if expected_lib in str(dlopen_calls) or 'libplugin.so' in str(dlopen_calls):
            print("\n*** SUCCESS: Library loading detected ***")
            return True
        else:
            print("\n*** FAILED: Library not detected ***")
            return False

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_single_benchmark()
    sys.exit(0 if success else 1)
