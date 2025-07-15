#!/usr/bin/env python3
import os
import json
import random
LABELED_DIR = "../../cert_data/labeled"
DATA_DIR = "../data"
TRAIN_FILE = os.path.join(DATA_DIR, "train.jsonl")
VAL_FILE = os.path.join(DATA_DIR, "val.jsonl")

# Create data directory if it doesn't exist
os.makedirs(DATA_DIR, exist_ok=True)

files = [f for f in os.listdir(LABELED_DIR) if f.endswith(".json")]
print(f"Found {len(files)} labeled cert files.")

# Shuffle files for random split
random.seed(200)  # Set seed for reproducibility
random.shuffle(files)

# Split files into training (95%) and validation (5%) sets
split_idx = int(len(files) * 0.95)
train_files = files[:split_idx]
val_files = files[split_idx:]

print(f"Split: {len(train_files)} files for training, {len(val_files)} files for validation")

train_count = 0
val_count = 0

# Process training files
with open(TRAIN_FILE, "w") as train_file:
    for fname in train_files:
        try:
            with open(os.path.join(LABELED_DIR, fname), "r") as f:
                data = json.load(f)

            flaws = data.get("flaws", [])
            pem = data.get("pem", "")

            # Format flaws exactly as your example
            if flaws:
                assistant_content = f"{{'flaws': {json.dumps(flaws)}}}"
            else:
                assistant_content = "{'flaws': []}"

            # Each record as required by Mistral instruct
            record = {
                "messages": [
                    {
                        "role": "user",
                        "content": pem
                    },
                    {
                        "role": "assistant",
                        "content": assistant_content
                    }
                ]
            }

            train_file.write(json.dumps(record) + "\n")
            train_count += 1

        except Exception as e:
            print(f"Failed on {fname}: {e}")

# Process validation files
with open(VAL_FILE, "w") as val_file:
    for fname in val_files:
        try:
            with open(os.path.join(LABELED_DIR, fname), "r") as f:
                data = json.load(f)

            flaws = data.get("flaws", [])
            pem = data.get("pem", "")

            # Format flaws exactly as your example
            if flaws:
                assistant_content = f"{{\"flaws\": {json.dumps(flaws)}}}"
            else:
                assistant_content = "{\"flaws\": []}"

            # Each record as required by Mistral instruct
            record = {
                "messages": [
                    {
                        "role": "user",
                        "content": pem
                    },
                    {
                        "role": "assistant",
                        "content": assistant_content
                    }
                ]
            }

            val_file.write(json.dumps(record) + "\n")
            val_count += 1

        except Exception as e:
            print(f"Failed on validation file {fname}: {e}")

print(f"✅ Generated {train_count} training and {val_count} validation Q&A pairs")
print(f"   Training data saved to: {TRAIN_FILE}")
print(f"   Validation data saved to: {VAL_FILE}")
