#!/usr/bin/env python3
import os
import json
import random
import re
from typing import List

LABELED_DIR = "../../cert_data/labeled"
OUTPUT_FILE = "../training_data/qa_pairs.json"

qa_pairs = []

# Checklist order and display names
FLAW_CATEGORIES = [
    ("expired", "Expired certificate"),
    ("sha1_signature", "SHA-1 signature algorithm"),
    ("low_entropy_serial", "Low entropy serial number"),
    ("short_key", "Short key length (less than 2048 bits)"),
    ("missing_SAN", "Missing Subject Alternative Name (SAN) extension")
]

# Detailed explanations for each flaw type
FLAW_EXPLANATIONS = {
    "expired": [
        "Found. The certificate has expired. Using expired certificates creates security risks as they may no longer be trusted by clients and browsers.",
        "Found. This certificate is expired. Expired certificates should be replaced immediately.",
        "Found. The certificate expired and continued use can lead to security warnings and potential vulnerabilities."
    ],
    "sha1_signature": [
        "Found. The certificate uses the SHA-1 algorithm for its signature, which is cryptographically weak and deprecated.",
        "Found. SHA-1 signature algorithm detected. This hashing algorithm is no longer considered secure due to collision vulnerabilities.",
        "Found. The certificate employs the deprecated SHA-1 signature algorithm. Modern security standards require stronger algorithms like SHA-256 or higher."
    ],
    "low_entropy_serial": [
        "Found. The certificate has a low entropy serial number, which could make it vulnerable to collision attacks.",
        "Found. Low entropy detected in the serial number. Serial numbers should be random to prevent predictability.",
        "Found. The serial number has low entropy, reducing the cryptographic strength of the certificate."
    ],
    "short_key": [
        "Found. The certificate uses a key that is only {key_length} bits long, below the recommended minimum of 2048 bits.",
        "Found. Short key detected ({key_length} bits). Keys should be at least 2048 bits to ensure adequate security.",
        "Found. The key length is insufficient at only {key_length} bits. Short keys are vulnerable to brute force attacks."
    ],
    "missing_SAN": [
        "Found. The certificate is missing the Subject Alternative Name (SAN) extension, which is required by modern browsers.",
        "Found. No SAN extension found. This can cause certificate validation failures in browsers.",
        "Found. The certificate lacks the required SAN extension and may not be trusted by modern systems."
    ]
}

# Not found explanations
NOT_FOUND_EXPLANATIONS = {
    "expired": "Not found.",
    "sha1_signature": "Not found.",
    "low_entropy_serial": "Not found.",
    "short_key": "Not found.",
    "missing_SAN": "Not found."
}

# Checklist-style instruction template
INSTRUCTION_TEMPLATE = (
    "Analyze the following X.509 certificate for these security flaws:\n"
    "- Expired certificate\n"
    "- SHA-1 signature algorithm\n"
    "- Low entropy serial number\n"
    "- Short key length (less than 2048 bits)\n"
    "- Missing Subject Alternative Name (SAN) extension\n\n"
    "For each flaw, respond with either \"Found\" and a brief explanation, or \"Not found\". Use this format:\n\n"
    "1. Expired certificate: [Found/Not found]. Explanation...\n"
    "2. SHA-1 signature algorithm: [Found/Not found]. Explanation...\n"
    "3. Low entropy serial number: [Found/Not found]. Explanation...\n"
    "4. Short key length: [Found/Not found]. Explanation...\n"
    "5. Missing SAN extension: [Found/Not found]. Explanation...\n\n"
    "Certificate:\n{pem}"
)

def extract_key_length(pem: str) -> str:
    key_match = re.search(r"Public-Key: \(([0-9]+) bit\)", pem)
    if key_match:
        return key_match.group(1)
    return "unknown"

def generate_checklist_answer(flaws: List[str], pem: str) -> str:
    flaw_set = set(flaws)
    key_length = extract_key_length(pem)
    checklist = []
    for idx, (flaw_key, display_name) in enumerate(FLAW_CATEGORIES, 1):
        if flaw_key in flaw_set:
            explanation = random.choice(FLAW_EXPLANATIONS[flaw_key])
            if flaw_key == "short_key":
                explanation = explanation.format(key_length=key_length)
            checklist.append(f"{idx}. {display_name}: {explanation}")
        else:
            checklist.append(f"{idx}. {display_name}: {NOT_FOUND_EXPLANATIONS[flaw_key]}")
    return "\n".join(checklist)

# Process certificate files
files = [f for f in os.listdir(LABELED_DIR) if f.endswith(".json")]
print(f"Found {len(files)} labeled cert files.")

for fname in files:
    try:
        with open(os.path.join(LABELED_DIR, fname), "r") as f:
            data = json.load(f)

        flaws = data.get("flaws", [])
        pem = data.get("pem", "")

        # Structured checklist instruction
        instruction = INSTRUCTION_TEMPLATE.format(pem=pem)
        question = f"<s>[INST] {instruction} [/INST]"
        answer = generate_checklist_answer(flaws, pem)
        qa_pairs.append({
            "question": question,
            "answer": answer
        })

    except Exception as e:
        print(f"Failed on {fname}: {e}")

print(f"Generated {len(qa_pairs)} checklist Q&A pairs.")

# Shuffle the QA pairs for better training
random.shuffle(qa_pairs)

# Write to output file
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, "w") as out:
    json.dump(qa_pairs, out, indent=2)

print(f"Saved {len(qa_pairs)} Q&A pairs to {OUTPUT_FILE}")
