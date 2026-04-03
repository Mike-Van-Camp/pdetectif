#!/usr/bin/env python3
"""
PDetectiF - Pure Python PDF Security Analysis Tool

Usage: python pdetectif.py [options] <pdf_file>

A comprehensive PDF security analysis tool that parses PDF binary
format directly without any external Python packages. Extracts
objects, streams, metadata, JavaScript, URLs, embedded files, and
provides risk scoring, anomaly detection, and entropy analysis.

Run with --help for full usage information.
"""

import sys
from pdetectif.cli import main

if __name__ == "__main__":
    sys.exit(main() or 0)
