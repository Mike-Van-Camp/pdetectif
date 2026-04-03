# PDetectiF

**Pure Python PDF Security Analysis Tool**

A comprehensive PDF analysis and security scanning tool that parses PDF binary format directly with **no external Python packages required**. Inspired by tools like `pdfid` and `pdfparser`, but goes significantly further with risk scoring, anomaly detection, entropy analysis, obfuscation detection, and more.

## Features

### Security Analysis
- **Keyword Scanning:** Detects security-relevant keywords (`/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`, `/JBIG2Decode`, and 20+ more)
- **Risk Scoring:** Automated 0-100 risk score with severity levels (LOW / MEDIUM / HIGH / CRITICAL) and detailed risk factors
- **Dangerous Pattern Detection:** Scans decoded streams for exploit indicators (`eval()`, `unescape()`, shellcode arrays, `String.fromCharCode`, known CVE patterns)
- **Obfuscation Detection:** Identifies hex-encoded PDF name objects (`/J#61vaScript` -> `/JavaScript`)
- **Decompression Bomb Detection:** Flags streams where decoded size vastly exceeds raw size or exceeds safe limits
- **Circular Reference Detection:** Identifies circular object references that may crash or exploit PDF readers

### Deep Analysis
- **Entropy Analysis:** Shannon entropy calculation for every stream to detect encrypted payloads, compressed shellcode, or steganographic content
- **Anomaly Detection:** Structural anomalies, format violations, xref mismatches, action chain depth analysis
- **Action Chain Analysis:** Traces action chains and reports action types (Launch, JavaScript, URI, etc.) at each level
- **Polyglot Detection:** Identifies PDF files masquerading as or embedded within other file formats (ZIP, PE, ELF, images, HTML)
- **Incremental Update Detection:** Finds multiple `%%EOF` markers and analyzes which objects were modified between updates
- **Encryption Strength Analysis:** Reports algorithm, key length, and security level (40-bit RC4 through AES-256) with permission flags

### Content Extraction
- **JavaScript Extraction:** Extracts JS from `/JS` actions, streams, string objects, and hex-encoded strings
- **URL/URI Extraction:** From `/URI` actions, annotations, stream content, and raw data
- **External Reference Tracking:** Detects `/GoToR`, `/SubmitForm`, `/ImportData`, and `/Launch` actions that reference external resources
- **Email Extraction:** Email addresses from all content sources
- **Domain & IP Extraction:** Domain names and IP addresses found in the document
- **Metadata Extraction:** Info dictionary, XMP metadata, document IDs, creation tools
- **Embedded File Detection:** Lists and extracts embedded/attached files
- **Form Field Extraction:** AcroForm fields, types, values, calculation scripts, and keystroke handlers
- **Font Analysis:** Detects embedded fonts, subsets, suspicious font streams with JavaScript-like content
- **QR Code Detection:** Identifies potential QR code images by properties; optionally decodes with Pillow + pyzbar

### PDF Parsing (Pure Python)
- **Full Binary Parser:** Tokenizer and recursive descent parser for all PDF object types
- **Stream Decompression:** FlateDecode (zlib), ASCIIHexDecode, ASCII85Decode, LZWDecode, RunLengthDecode, with predictor support
- **Cross-Reference Parsing:** Traditional xref tables and cross-reference streams (PDF 1.5+)
- **Object Stream Parsing:** Extracts objects from compressed object streams
- **Encryption Detection:** Identifies and reports encryption parameters

### Forensics
- **File Hashing:** MD5, SHA-1, SHA-256 of the PDF file (single-pass computation)
- **Hex Dump:** Full file and per-object stream hex dumps
- **Object Tree View:** Complete object hierarchy display
- **Raw Content View:** Direct access to raw PDF bytes
- **JSON Output:** Machine-readable output for all analysis modes
- **CSV Output:** Tabular output for batch analysis results
- **PDF Comparison:** Diff two PDFs by structure, objects, and risk score

### Automation
- **Batch Processing:** Analyze all PDFs in a directory with summary table output
- **CI/CD Integration:** `--fail-above N` exits with code 1 when risk score exceeds threshold
- **Color Output:** ANSI-colored severity levels with auto-detection and `--no-color` flag

## Installation

No installation of external packages needed. Just clone and run:

```bash
git clone https://github.com/Mike-Van-Camp/pdetectif.git
cd pdetectif
python pdetectif.py --help
```

## Usage

```bash
# Default: Security scan with risk score
python pdetectif.py document.pdf

# Full analysis (all checks combined)
python pdetectif.py -f document.pdf

# Security keyword scan
python pdetectif.py -s document.pdf

# Extract JavaScript
python pdetectif.py -j document.pdf

# Extract URLs
python pdetectif.py -u document.pdf

# Extract metadata
python pdetectif.py -m document.pdf

# Extract email addresses
python pdetectif.py -e document.pdf

# List embedded files
python pdetectif.py -E document.pdf

# Extract embedded files to a directory
python pdetectif.py --extract-files output_dir/ document.pdf

# Entropy analysis
python pdetectif.py --entropy document.pdf

# Anomaly and polyglot detection
python pdetectif.py --anomaly document.pdf

# Extract form fields and actions
python pdetectif.py --forms document.pdf

# Analyze fonts
python pdetectif.py --fonts document.pdf

# QR code detection
python pdetectif.py --qr document.pdf

# Show specific object
python pdetectif.py -o 5 document.pdf

# Hex dump of object stream
python pdetectif.py -D 5 document.pdf

# Object tree overview
python pdetectif.py --tree document.pdf

# List all streams
python pdetectif.py --streams document.pdf

# List all images
python pdetectif.py --images document.pdf

# Extract domains and IPs
python pdetectif.py --domains document.pdf

# Hex dump of file
python pdetectif.py --hexdump document.pdf

# JSON output (works with any mode)
python pdetectif.py --json -f document.pdf

# Verbose output (show all keywords including zero-count)
python pdetectif.py -v document.pdf

# Batch analyze all PDFs in a directory
python pdetectif.py --batch pdfs/

# Compare two PDFs
python pdetectif.py --diff other.pdf document.pdf

# CI/CD: fail if risk score exceeds threshold
python pdetectif.py --fail-above 50 document.pdf

# CSV output for batch results
python pdetectif.py --csv --batch pdfs/

# Disable colored output
python pdetectif.py --no-color -f document.pdf
```

## Output Example

```
  ____  ____       _            _   _ _____
 |  _ \|  _ \  ___| |_ ___  ___| |_(_)  ___|
 | |_) | | | |/ _ \ __/ _ \/ __| __| | |_
 |  __/| |_| |  __/ ||  __/ (__| |_| |  _|
 |_|   |____/ \___|\__\___|\___|\__|_|_|

        PDF Security Analysis Report
==================================================

── Document Info ──
  File:          suspicious.pdf
  Size:          45.2 KB
  PDF Version:   1.7
  Pages:         1
  Objects:       12
  Streams:       3
  Encrypted:     No
  Linearized:    No

── Suspicious Keywords ──
  /JS               2 ⚠
  /JavaScript        1 ⚠
  /OpenAction        1 ⚠
  /AA                0
  /Launch            0

── Risk Assessment ──
  Score:  55/100  [███████████░░░░░░░░░]  [HIGH]
  Factors:
    • JavaScript detected (3 reference(s))
    • Auto-execute actions (1)
```

## Architecture

```
pdetectif/
├── pdetectif.py                 # Entry point
├── pdetectif/
│   ├── __init__.py              # Package version
│   ├── cli.py                   # Command-line interface
│   ├── utils.py                 # Hex dump, formatting utilities
│   ├── core/
│   │   ├── parser.py            # PDF binary parser
│   │   ├── objects.py           # PDF object type classes
│   │   └── stream.py            # Stream filter decompression
│   ├── analysis/
│   │   ├── scanner.py           # Security keyword scanner
│   │   ├── entropy.py           # Entropy analysis
│   │   └── anomaly.py           # Anomaly & polyglot detection
│   └── extraction/
│       ├── javascript.py        # JavaScript extraction
│       ├── urls.py              # URL, email, domain, external ref extraction
│       ├── metadata.py          # Metadata extraction
│       ├── embedded.py          # Embedded file extraction
│       ├── forms.py             # AcroForm / XFA field extraction
│       ├── fonts.py             # Font analysis and anomaly detection
│       └── qrcodes.py           # QR code detection and decoding
├── requirements.txt             # Empty (no dependencies)
└── README.md
```

## Requirements

- Python 3.7+
- No external packages for core functionality (uses only `re`, `zlib`, `struct`, `hashlib`, `math`, `json`, `argparse`, `os`, `sys`, `csv`, `io` from stdlib)
- Optional: `Pillow` + `pyzbar` for QR code decoding (heuristic detection works without them)
