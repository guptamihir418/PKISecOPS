#!/usr/bin/env python3
import os
import json
import random

LABELED_DIR = "../../cert_data/labeled"
OUTPUT_FILE = "../training_data/qa_pairs.json"

qa_pairs = []

# Diverse ways to ask about cert flaws
QUESTION_TEMPLATES = [
    "Does this certificate have any issues?",
    "What problems, if any, does this certificate have?",
    "List all security flaws found in this certificate.",
    "Are there any weaknesses or policy violations in this certificate?",
    "Does this certificate violate any PKI best practices?",
    "Can you identify compliance issues with this certificate?"
]

files = [f for f in os.listdir(LABELED_DIR) if f.endswith(".json")]
print(f"Found {len(files)} labeled cert files.")

for fname in files:
    try:
        with open(os.path.join(LABELED_DIR, fname), "r") as f:
            data = json.load(f)

        flaws = data.get("flaws", [])
        pem = data.get("pem", "")

        # Randomly pick a question phrasing for this example
        question = random.choice(QUESTION_TEMPLATES)

        if flaws:
            answer = f"Yes, it has these issues: {', '.join(flaws)}."
        else:
            answer = "No, this certificate does not have any known issues."

        qa_pairs.append({
            "question": question,
            "context": pem,
            "answer": answer
        })

    except Exception as e:
        print(f"Failed on {fname}: {e}")

print(f"Generated {len(qa_pairs)} diversified Q&A pairs.")

# Write to output file
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, "w") as out:
    json.dump(qa_pairs, out, indent=2)

print(f"Saved Q&A pairs to {OUTPUT_FILE}")
