#!/usr/bin/env python3
"""
hex_to_decimal.py: Convert mbedtls hex dumps for MPI and EC points to decimal values.

Usage:
  python hex_to_decimal.py [options] <input_file>

Modes:
  -M, --mpi      Treat input as an MPI hex dump and print its decimal value.
  -E, --ecp      Treat input as an uncompressed EC point (0x04||X||Y) and print X and Y in decimal.

Input format:
  Lines containing two-digit hex bytes, optionally with C-style formatting.
  Anything after `|` on a line is ignored.

Examples:
  python hex_to_decimal.py -M dump.txt
  python hex_to_decimal.py -E point_dump.txt
"""
import sys
import re
import argparse


def print_help():
    print(__doc__)

def read_input(path):
    data = sys.stdin.read() if path == '-' else open(path, 'r', encoding='utf-8').read()
    return data.splitlines()


def parse_hex_lines(lines):
    tokens = []
    for line in lines:
        # strip comments after |
        if '|' in line:
            line = line.split('|', 1)[0]
        # find all two-digit hex tokens
        tokens.extend(re.findall(r'\b([0-9A-Fa-f]{2})\b', line))
    return tokens


def tokens_to_bytes(tokens):
    return bytes(int(t, 16) for t in tokens)


def handle_mpi(tokens):
    data = tokens_to_bytes(tokens)
    # big-endian integer
    value = int.from_bytes(data, 'big')
    print(value)


def handle_ecp(tokens):
    data = tokens_to_bytes(tokens)
    if not data:
        print("Error: Empty input for EC point.", file=sys.stderr)
        sys.exit(1)
    # uncompressed point tag
    if data[0] != 0x04:
        print(f"Error: Expected uncompressed EC point with leading 0x04, got 0x{data[0]:02X}", file=sys.stderr)
        sys.exit(1)
    # remaining bytes split equally to X and Y
    coord_bytes = data[1:]
    if len(coord_bytes) % 2 != 0:
        print("Error: EC point coordinate length is not even.", file=sys.stderr)
        sys.exit(1)
    half = len(coord_bytes) // 2
    x_bytes = coord_bytes[:half]
    y_bytes = coord_bytes[half:]
    x = int.from_bytes(x_bytes, 'big')
    y = int.from_bytes(y_bytes, 'big')
    print(f"X = {x}\nY = {y}")


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-M', '--mpi', action='store_true', help='Convert MPI hex dump to decimal')
    parser.add_argument('-E', '--ecp', action='store_true', help='Convert EC point dump to decimal X/Y')
    parser.add_argument('input_file', help="Path to input file ('-' for stdin)")
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message')
    args = parser.parse_args()

    if args.help or (not args.mpi and not args.ecp):
        print_help()
        sys.exit(0)

    lines = read_input(args.input_file)
    tokens = parse_hex_lines(lines)
    if not tokens:
        print("Error: No hex bytes found in input.", file=sys.stderr)
        sys.exit(1)

    if args.mpi:
        handle_mpi(tokens)
    else:
        handle_ecp(tokens)


if __name__ == '__main__':
    main()
