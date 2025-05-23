#!/usr/bin/env python3
import sys
import re
import textwrap

def print_help():
    print(textwrap.dedent("""
    Usage:
      # Read from a file:
      python hex_to_c_array.py <input_file>

    Input format:
      Lines containing groups of two‐digit hex bytes, e.g.
         0c 40 f5 ff 9d 5a be fc  c6 9f 84 0d f2 46 84 96 |.@...Z.. .....F..
         cf 8c 47 eb 30 6d 4d 20  2f f5 d3 7c 71 99 3e 13 |..G.0mM  /..|q.>.
      Anything after a '|' is ignored; any non‐hex text is skipped.

    Output:
      A formatted C-style array:
        uint8_t keyCode[] = {
            0x0C, 0x40, …, 0x13
        };
    """))

def read_input(path):
    if path == '-':
        return sys.stdin.read().splitlines()
    else:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().splitlines()

def parse_hex_lines(lines):
    """
    For each line:
      - strip off anything after '|'
      - find all two‐digit hex tokens
    Returns a flat list of hex‐byte strings, e.g. ['0c','40', ...]
    """
    tokens = []
    for line in lines:
        # drop ASCII dump
        if '|' in line:
            line = line.split('|', 1)[0]
        # find all 2‐digit hex tokens
        toks = re.findall(r'\b([0-9A-Fa-f]{2})\b', line)
        tokens.extend(toks)
    return tokens

def format_c_array(tokens, var_name='keyCode'):
    arr = [f"0x{t.upper()}" for t in tokens]
    print(f"uint8_t {var_name}[] = {{")
    for i in range(0, len(arr), 16):
        chunk = arr[i:i+16]
        sep = "," if i + 16 < len(arr) else ""
        print("    " + ", ".join(chunk) + sep)
    print("};")

def main():
    if len(sys.argv) != 2 or sys.argv[1] in ('-h', '--help'):
        print_help()
        sys.exit(0)

    path = sys.argv[1]
    lines = read_input(path)
    tokens = parse_hex_lines(lines)
    if not tokens:
        print("Error: No hex bytes found in input.", file=sys.stderr)
        sys.exit(1)
    format_c_array(tokens)

if __name__ == "__main__":
    main()
