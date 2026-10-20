#!/usr/bin/env python3
"""ARGUS launcher. No arguments: interactive menu. With arguments: scriptable CLI."""
import sys

from scanner.menu import main

if __name__ == "__main__":
    sys.exit(main())
