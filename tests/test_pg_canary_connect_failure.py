#!/usr/bin/env python3
"""F56: yuzu_pg_canary must print a FIXED cause on a connect failure, never libpq's text (which
quotes the host, port and dbname parsed from the DSN). argv[1] = path to the canary binary."""
import subprocess
import sys

MARK = "yuzu_test_canary_secretdb"


def main():
    exe = sys.argv[1]
    r = subprocess.run([exe, f"host=127.0.0.1 port=1 dbname={MARK} user=u connect_timeout=2"],
                       capture_output=True, text=True, timeout=30)
    err = r.stderr
    ok = (r.returncode == 1 and "canary: connect failed: " in err and "server not reachable" in err
          and MARK not in err and "127.0.0.1" not in err and err.endswith("\n"))
    if not ok:
        print("FAIL: rc=%s stderr=%r" % (r.returncode, err))
        return 1
    print("OK: canary connect failure prints a fixed cause")
    return 0


if __name__ == "__main__":
    sys.exit(main())
