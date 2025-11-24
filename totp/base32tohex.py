#!/usr/bin/env python3
import sys
import base64

def main():
    if len(sys.argv) != 2:
        print("usage: base32tohex.py BASE32STRING", file=sys.stderr)
        sys.exit(1)

    b32 = sys.argv[1].strip().upper()

    try:
        raw = base64.b32decode(b32)
    except Exception as e:
        print(f"decode error: {e}", file=sys.stderr)
        sys.exit(2)

    print(raw.hex())

if __name__ == "__main__":
    main()
