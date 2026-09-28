#!/usr/bin/env python3
"""Catch use-before-definition in the single-TU C sources.

MSVC compiles these as C, where a macro or static function must appear before
its first use. gcc on Linux cannot check the Windows-only files, so this does a
textual pass instead: for every #define and every static function definition,
assert nothing references it on an earlier line. This is exactly the class of
error that produced 'C2065: PF_ORIGIN_HALVED: undeclared identifier'.
"""
import re, sys, glob

def strip_noncode(text):
    """Blank out comments and string literals, preserving line structure."""
    out, i, n = [], 0, len(text)
    state = 'code'
    while i < n:
        c = text[i]; nx = text[i+1] if i+1 < n else ''
        if state == 'code':
            if c == '/' and nx == '/': state = 'line'; out.append('  '); i += 2; continue
            if c == '/' and nx == '*': state = 'block'; out.append('  '); i += 2; continue
            if c == '"': state = 'str'; out.append(' '); i += 1; continue
            out.append(c); i += 1; continue
        if state == 'line':
            if c == '\n': state = 'code'; out.append('\n')
            else: out.append(' ')
            i += 1; continue
        if state == 'block':
            if c == '*' and nx == '/': state = 'code'; out.append('  '); i += 2; continue
            out.append('\n' if c == '\n' else ' '); i += 1; continue
        if state == 'str':
            if c == '\\': out.append('  '); i += 2; continue
            if c == '"': state = 'code'
            out.append('\n' if c == '\n' else ' '); i += 1; continue
    return ''.join(out)

fails = 0
checks = 0
for path in sorted(glob.glob('../src/*.c')) or sorted(glob.glob('src/*.c')):
    lines = strip_noncode(open(path, encoding='utf-8', errors='replace').read()).split('\n')

    defined = {}
    for ln, line in enumerate(lines, 1):
        m = re.match(r'\s*#\s*define\s+([A-Za-z_]\w*)', line)
        if m: defined.setdefault(m.group(1), ln)
        # static function DEFINITION (has a body brace on the same line or is a
        # bare signature line ending in '{' or ')')
        m = re.match(r'\s*static\s+[A-Za-z_][\w \t\*]*?([A-Za-z_]\w*)\s*\(', line)
        if m: defined.setdefault(m.group(1), ln)

    for name, defline in defined.items():
        if not (name.startswith('PF_') or name.startswith('pf_') or
                name.startswith('width_cache') or name.startswith('cache_')):
            continue
        checks += 1
        pat = re.compile(r'\b' + re.escape(name) + r'\b')
        for ln in range(1, defline):
            line = lines[ln-1]
            if pat.search(line):
                # a forward declaration (prototype ending in ';') is fine
                if re.match(r'\s*(static|extern)?[\w \t\*]*' + re.escape(name) + r'\s*\([^;]*\)\s*;\s*$', line):
                    continue
                print(f"FAIL: {path}:{ln} uses '{name}' but it is defined at line {defline}")
                print(f"      {line.strip()[:90]}")
                fails += 1
                break

print(f"definition-order check: {checks} symbols, {fails} failures")
sys.exit(1 if fails else 0)
