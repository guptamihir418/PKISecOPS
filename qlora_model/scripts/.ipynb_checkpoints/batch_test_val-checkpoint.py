#!/usr/bin/env python3
"""
Batch test your fine-tuned model on qlora_model/data/val.jsonl

- Loads your val.jsonl (same format as your training)
- Passes each PEM through your model
- Writes results to val_predictions.csv for easy analysis

Author: Mihir Gupta, 2025
"""

import json
import csv
from tqdm import tqdm
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

# ==============================
# CONFIG
# ==============================
VAL_FILE = "../data/val.jsonl"  # adjust if needed
BASE_MODEL = "mistralai/Mistral-7B-Instruct-v0.1"
ADAPTER_DIR = "../model_weights"
OUT_CSV = "val_predictions.csv"
MAX_NEW_TOKENS = 128

# ==============================
# Load tokenizer & model
# ==============================
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4"
)

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
tokenizer.pad_token = tokenizer.eos_token

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map="auto"
)

model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
model = model.merge_and_unload()
model.eval()

device = "cuda" if torch.cuda.is_available() else "cpu"

# ==============================
# Load val data
# ==============================
with open(VAL_FILE) as f:
    val_data = [json.loads(line) for line in f]

# ==============================
# Run through model
# ==============================
results = []

for idx, example in tqdm(enumerate(val_data), total=len(val_data), desc="Batch testing"):
    pem = example["messages"][0]["content"]
    expected = example["messages"][1]["content"]

    # Build exact same prompt
    prompt = f"<s>[INST] {pem} [/INST]"

    inputs = tokenizer(prompt, return_tensors="pt").to(device)

    with torch.no_grad():
        outputs = model.generate(
            input_ids=inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_new_tokens=MAX_NEW_TOKENS,
            temperature=0.0,
            do_sample=False
        )
    decoded = tokenizer.decode(outputs[0], skip_special_tokens=False)

    # Extract after [/INST]
    if "[/INST]" in decoded:
        predicted = decoded.split("[/INST]", 1)[1].strip()
    else:
        predicted = decoded.strip()

    results.append({
        "index": idx,
        "expected_flaws": expected,
        "predicted_flaws": predicted
    })

# ==============================
# Write CSV
# ==============================
with open(OUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["index", "expected_flaws", "predicted_flaws"])
    writer.writeheader()
    for row in results:
        writer.writerow(row)

print(f"✅ Finished batch testing. Results saved to {OUT_CSV}")
