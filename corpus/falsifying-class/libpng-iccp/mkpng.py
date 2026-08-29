import os
import struct
import sys
import zlib


def chunk(typ, data):
    c = typ + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

keyword = (sys.argv[1] if len(sys.argv) > 1 else "ICC Profile").encode()
out     = sys.argv[2] if len(sys.argv) > 2 else "/tmp/t.png"
psize   = int(sys.argv[3]) if len(sys.argv) > 3 else 400

# Incompressible profile body so the iCCP chunk is comfortably longer than the
# 81-byte read window, otherwise libpng bails with "iCCP: too short" before it
# ever parses the keyword.
profile = os.urandom(psize)
ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
iccp = keyword + b"\0" + b"\0" + zlib.compress(profile, 0)
idat = zlib.compress(b"\0\xff\x00\x00")

png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"iCCP", iccp)
       + chunk(b"IDAT", idat) + chunk(b"IEND", b""))
open(out, "wb").write(png)
print(f"{os.path.basename(out)}: keyword={keyword.decode()!r} ({len(keyword)}B), iCCP chunk={len(iccp)}B")
