#!/usr/bin/env python3
"""
gen_vendordb.py - compile the USB-IF vendor list into a C table for pnpfuzz.

pnpfuzz ships as a single static exe with no side files, so the vendor list is
baked in rather than loaded at runtime: a lookup is then a binary search over an
in-memory table, needs no network, and cannot go missing on a bare VM.

Input is the VendorAPI SQLite database (or its .sql dump) built from the USB-IF
vendor ID list. Output is src/vendordb.h.

    python3 tools/gen_vendordb.py data/vendors.db src/vendordb.h

Two parallel sorted arrays are emitted rather than one big string blob: MSVC caps
a single string literal at 65535 bytes, and the concatenated names run to ~315KB,
so one blob would fail to compile. Individual literals sidestep that entirely.

Regenerate when USB-IF publishes a new list: update data/vendors.db (a SQLite
table of Company, VendorID) or an equivalent .sql dump, then run:
    python3 tools/gen_vendordb.py data/vendors.db src/vendordb.h
"""

import os
import re
import sqlite3
import sys


def load_rows(path):
    """Read (vid, company) pairs from a .db or a .sql dump."""
    if path.endswith(".sql"):
        text = open(path, encoding="utf-8").read()
        rows = []
        # ('Company Name', '0x046D')  - company may contain escaped quotes ('')
        for m in re.finditer(r"\('((?:[^']|'')*)',\s*'(0x[0-9A-Fa-f]{4})'\)", text):
            rows.append((m.group(2), m.group(1).replace("''", "'")))
        return rows
    con = sqlite3.connect(path)
    try:
        return [(v, c) for c, v in
                con.execute("SELECT Company, VendorID FROM vendors")]
    finally:
        con.close()


def c_escape(s):
    """Escape for a C string literal. Non-ASCII is emitted as hex escapes of the
    UTF-8 bytes, followed by "" so a following hex digit cannot be swallowed into
    the escape - '\\xC3BC' would otherwise parse as one huge character."""
    out = []
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch in ("\r", "\n"):
            out.append(" ")
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("".join("\\x%02X" % b for b in ch.encode("utf-8")) + '""')
    return "".join(out)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "data/vendors.db"
    dst = sys.argv[2] if len(sys.argv) > 2 else "src/vendordb.h"

    rows = load_rows(src)
    if not rows:
        sys.exit("no vendor rows found in " + src)

    # Drop exact duplicates; keep genuinely different names for the same VID
    # (a handful of vendors are listed twice under different legal entities).
    seen = set()
    uniq = []
    for vid, company in rows:
        company = " ".join(company.split())
        key = (vid.upper(), company)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((int(vid, 16), company))

    uniq.sort(key=lambda r: (r[0], r[1]))

    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write("/*\n")
        f.write(" * vendordb.h - USB-IF vendor ID table, GENERATED. Do not edit by hand.\n")
        f.write(" *\n")
        f.write(" * Regenerate with: python3 tools/gen_vendordb.py data/vendors.db "
                "src/vendordb.h\n")
        f.write(" *\n")
        f.write(" * Sorted ascending by vendor ID so a lookup is a binary search. A VID may\n")
        f.write(" * legitimately appear more than once (same silicon vendor, different legal\n")
        f.write(" * entity), so equal keys are adjacent and the search walks back to the first.\n")
        f.write(" *\n")
        f.write(" * USB-IF only. PCI vendor IDs are a separate PCI-SIG registry and are NOT\n")
        f.write(" * in this table - a PCI lookup must not consult it.\n")
        f.write(" */\n\n")
        f.write("#ifndef PNPFUZZ_VENDORDB_H\n#define PNPFUZZ_VENDORDB_H\n\n")
        f.write("#define PF_VENDORDB_COUNT %d\n" % len(uniq))
        f.write('#define PF_VENDORDB_SOURCE "USB-IF vendor ID list"\n\n')

        f.write("static const unsigned short pf_vendordb_vid[PF_VENDORDB_COUNT] = {\n")
        for i in range(0, len(uniq), 12):
            chunk = uniq[i:i + 12]
            f.write("    " + ",".join("0x%04X" % v for v, _ in chunk) + ",\n")
        f.write("};\n\n")

        f.write("static const char *const pf_vendordb_name[PF_VENDORDB_COUNT] = {\n")
        for _, name in uniq:
            f.write('    "%s",\n' % c_escape(name))
        f.write("};\n\n")
        f.write("#endif /* PNPFUZZ_VENDORDB_H */\n")

    print("wrote %s: %d vendors from %s" % (dst, len(uniq), src))


if __name__ == "__main__":
    main()
