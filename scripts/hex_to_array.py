#!/usr/bin/env python3
"""
hex_to_array.py: Convert Zephyr debug hex dumps to C uint8_t arrays or strings.

Usage:
  # Uppercase hex string:
  python hex_to_array.py -U <input_file>

  # C-style array (default name 'keyCode'):
  python hex_to_array.py -C [-n VAR_NAME] <input_file>

Modes:
  -U, --upper   Emit a single uppercase hex string.
  -C, --carray  Emit a formatted C array.
  -n, --name    (Only for -C) Set the C array variable name.

Input format:
  Lines containing two-digit hex bytes, e.g.
     0c 40 f5 ff 9d 5a be fc  c6 9f 84 0d f2 46 84 96 |.@...Z.. .....F..
     cf 8c 47 eb 30 6d 4d 20  2f f5 d3 7c 71 99 3e 13 |..G.0mM  /..|q.>.
  Anything after ‘|’ is ignored.
"""
import sys
import re
import textwrap
import argparse

def print_help():
    print(__doc__)

def read_input(path):
    data = sys.stdin.read() if path == '-' else open(path, 'r', encoding='utf-8').read()
    return data.splitlines()

def parse_hex_lines(lines):
    tokens = []
    for line in lines:
        if '|' in line:
            line = line.split('|', 1)[0]
        tokens.extend(re.findall(r'\b([0-9A-Fa-f]{2})\b', line))
    return tokens

def format_hex_string(tokens):
    print(''.join(tokens).upper())

def format_c_array(tokens, var_name='keyCode'):
    count = len(tokens)
    arr = [f"0x{t.upper()}" for t in tokens]
    print(f"uint8_t {var_name}[{count}] = {{")
    for i in range(0, count, 16):
        chunk = arr[i:i+16]
        sep = ',' if i + 16 < count else ''
        print('    ' + ', '.join(chunk) + sep)
    print("};")

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-U', '--upper',  action='store_true', help='Output uppercase hex string')
    parser.add_argument('-C', '--carray', action='store_true', help='Output C-style array')
    parser.add_argument('-n', '--name',   default='keyCode',
                        help='Variable name for C array (only used with -C)')
    parser.add_argument('input_file', help="Path to input file (use '-' for stdin)")
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message')
    args = parser.parse_args()

    if args.help or (not args.upper and not args.carray):
        print_help()
        sys.exit(0)

    lines = read_input(args.input_file)
    tokens = parse_hex_lines(lines)
    if not tokens:
        print("Error: No hex bytes found in input.", file=sys.stderr)
        sys.exit(1)

    if args.upper:
        format_hex_string(tokens)
    else:
        format_c_array(tokens, args.name)

if __name__ == '__main__':
    main()
