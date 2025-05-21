#!/usr/bin/env python3

import sys
import textwrap

def print_help():
    help_text = """
    Usage:
      python hex_to_c_array.py HEX_STRING

    Arguments:
      HEX_STRING    A string of hexadecimal characters (no spaces), e.g.:
                    026E3C3B96111EE52998269C...

    Output:
      A well-formatted C-style uint8_t array definition without a trailing comma.

    Example:
      python hex_to_c_array.py 026E3C3B9611...
    """
    print(textwrap.dedent(help_text))

def hex_to_c_array(hex_string):
    if len(hex_string) % 2 != 0:
        print("Error: Hex string must have an even number of characters.")
        sys.exit(1)

    try:
        bytes_array = [f"0x{hex_string[i:i+2]}" for i in range(0, len(hex_string), 2)]
    except Exception as e:
        print(f"Error: Failed to process hex string — {e}")
        sys.exit(1)

    print("uint8_t keyCode[] = \n{")
    for i in range(0, len(bytes_array), 16):
        line = bytes_array[i:i+16]
        if i + 16 >= len(bytes_array):  # last line
            print("    " + ", ".join(line))
        else:
            print("    " + ", ".join(line) + ",")
    print("};")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print_help()
        sys.exit(0)

    hex_string = sys.argv[1].strip().replace(" ", "").replace("\n", "")
    hex_to_c_array(hex_string)

if __name__ == "__main__":
    main()
