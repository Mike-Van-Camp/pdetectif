# PDetectiF

**Pure Python PDF Security Analysis Tool**

A comprehensive PDF analysis and security scanning tool that parses PDF binary format directly — **no external Python packages required**. Inspired by tools like `pdfid` and `pdfparser`, but goes significantly further with risk scoring, anomaly detection, entropy analysis, obfuscation detection, and more.

## Features

### Security Analysis
- **Keyword Scanning** — Detects security-relevant keywords (`/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`, `/JBIG2Decode`, and 20+ more)
- **Risk Scoring** — Automated 0-100 risk score with severity levels (LOW / MEDIUM / HIGH / CRITICAL) and detailed risk factors
- **Dangerous Pattern Detection** — Scans decoded streams for exploit indicators (`eval()`, `unescape()`, shellcode arrays, `String.fromCharCode`, known CVE patterns)
- **Obfuscation Detection** — Identifies hex-encoded PDF name objects (`/J#61vaScript` → `/JavaScript`)

### Deep Analysis
- **Entropy Analysis** — Shannon entropy calculation for every stream to detect encrypted payloads, compressed shellcode, or steganographic content
- **Anomaly Detection** — Structural anomalies, format violations, xref mismatches, action chain depth analysis
- **Polyglot Detection** — Identifies PDF files masquerading as or embedded within other file formats (ZIP, PE, ELF, images, HTML)
- **Incremental Update Detection** — Finds multiple `%%EOF` markers and xref tables indicating document manipulation

### Content Extraction
- **JavaScript Extraction** — Extracts JS from `/JS` actions, streams, string objects, and hex-encoded strings
- **URL/URI Extraction** — From `/URI` actions, annotations, stream content, and raw data
- **Email Extraction** — Email addresses from all content sources
- **Domain & IP Extraction** — Domain names and IP addresses found in the document
- **Metadata Extraction** — Info dictionary, XMP metadata, document IDs, creation tools
- **Embedded File Detection** — Lists and extracts embedded/attached files

### PDF Parsing (Pure Python)
- **Full Binary Parser** — Tokenizer and recursive descent parser for all PDF object types
- **Stream Decompression** — FlateDecode (zlib), ASCIIHexDecode, ASCII85Decode, LZWDecode, RunLengthDecode, with predictor support
- **Cross-Reference Parsing** — Traditional xref tables and cross-reference streams (PDF 1.5+)
- **Object Stream Parsing** — Extracts objects from compressed object streams
- **Encryption Detection** — Identifies and reports encryption parameters

### Forensics
- **File Hashing** — MD5, SHA-1, SHA-256 of the PDF file
- **Hex Dump** — Full file and per-object stream hex dumps
- **Object Tree View** — Complete object hierarchy display
- **Raw Content View** — Direct access to raw PDF bytes
- **JSON Output** — Machine-readable output for all analysis modes

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
```

## Output Example

```
=================================================================
  PDetectiF - PDF Security Analysis Report
=================================================================

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
│       ├── urls.py              # URL, email, domain extraction
│       ├── metadata.py          # Metadata extraction
│       └── embedded.py          # Embedded file extraction
├── requirements.txt             # Empty (no dependencies)
└── README.md
```

## Requirements

- Python 3.7+
- No external packages (uses only `re`, `zlib`, `struct`, `hashlib`, `math`, `json`, `argparse`, `os`, `sys` from stdlib)
