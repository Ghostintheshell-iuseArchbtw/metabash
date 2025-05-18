import requests
import hashlib
import json
from collections import defaultdict
import difflib
import os

API_KEY = 'metabash_secure_key_2024'
API_URL = 'http://"yourhost":8080/x7y9z2'

def get_payload():
    headers = {'x-api-key': API_KEY}
    response = requests.post(API_URL, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def calculate_hash(content):
    return hashlib.sha256(content.encode()).hexdigest()

def compare_payloads(payloads):
    # Compare each payload with every other payload
    comparisons = defaultdict(list)
    for i, (name1, content1) in enumerate(payloads.items()):
        for j, (name2, content2) in enumerate(payloads.items()):
            if i < j:  # Avoid comparing with self and avoid duplicate comparisons
                diff = list(difflib.unified_diff(
                    content1.splitlines(),
                    content2.splitlines(),
                    fromfile=name1,
                    tofile=name2,
                    lineterm=''
                ))
                if diff:
                    comparisons[f"{name1} vs {name2}"] = diff

    return comparisons

def main():
    print("Generating 10 payloads...")
    payloads = {}
    hashes = {}
    
    # Generate 10 payloads
    for i in range(10):
        print(f"Generating payload {i+1}/10...")
        result = get_payload()
        if result and result['status'] == 'success':
            filename = result['filename']
            content = result['script']
            payloads[filename] = content
            hashes[filename] = calculate_hash(content)
        else:
            print(f"Failed to generate payload {i+1}")
            continue

    # Print hashes
    print("\nPayload Hashes:")
    print("-" * 80)
    for filename, hash_value in hashes.items():
        print(f"{filename}: {hash_value}")

    # Compare payloads
    print("\nComparing payloads...")
    comparisons = compare_payloads(payloads)
    
    # Print comparison results
    print("\nPayload Comparisons:")
    print("-" * 80)
    for comparison, diffs in comparisons.items():
        print(f"\n{comparison}:")
        print("-" * 40)
        for diff in diffs:
            print(diff)

    # Save results to files
    with open('payload_hashes.txt', 'w') as f:
        json.dump(hashes, f, indent=2)

    with open('payload_comparisons.txt', 'w') as f:
        for comparison, diffs in comparisons.items():
            f.write(f"\n{comparison}:\n")
            f.write("-" * 40 + "\n")
            for diff in diffs:
                f.write(diff + "\n")

    print("\nResults have been saved to payload_hashes.txt and payload_comparisons.txt")

if __name__ == "__main__":
    main() 
