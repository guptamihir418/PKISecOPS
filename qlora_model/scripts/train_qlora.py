#!/usr/bin/env python3
"""
================================================================================
train_qlora.py

Fine-tunes Mistral-7B with QLoRA on your structured X.509 cert Q&A pairs.

- Loads JSON data from training_data/qa_pairs.json
- Tokenizes question+context as input, expects answer as label
- Trains with PEFT QLoRA on bitsandbytes 4-bit quantized model
- Saves adapter weights and tokenizer in safetensors format

Author: Mihir Gupta, 2025
For AI Certificate Service POC (PKISecOPS project)
================================================================================
"""

import json
import random
import numpy as np
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer
from peft import prepare_model_for_kbit_training, LoraConfig, get_peft_model
import torch
import os

import transformers
from transformers import TrainingArguments
print("Transformers version:", transformers.__version__)
print("Transformers path:", transformers.__file__)
print("TrainingArguments module:", TrainingArguments.__module__)
print("TrainingArguments doc:", TrainingArguments.__doc__[:200])

# =================================================================================
# Paths & Hyperparams
# =================================================================================
DATA_FILE = "../training_data/qa_pairs.json"
MODEL_OUT_DIR = "../model_weights/"
MODEL_NAME = "mistralai/Mistral-7B-Instruct-v0.1"

BATCH_SIZE = 2
GRADIENT_ACCUMULATION_STEPS = 4
EPOCHS = 2
LEARNING_RATE = 3e-4
WARMUP_RATIO = 0.03
VAL_SPLIT = 0.05  # 5% for validation

# =================================================================================
# 0️⃣ Reproducibility
# =================================================================================
SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

# =================================================================================
# 1️⃣ Load and Validate JSON Data
# =================================================================================
with open(DATA_FILE, "r") as f:
    data = json.load(f)

if not data:
    raise ValueError("No training data found in qa_pairs.json!")

records = []
for item in data:
    if "question" in item and "answer" in item:
        records.append({"prompt": item["question"], "response": item["answer"]})
    else:
        print("Warning: Skipping malformed item:", item)

if not records:
    raise ValueError("No valid Q&A pairs found in dataset!")

print(f"Loaded {len(records)} Q&A pairs.")
print("Sample record:", records[0])

# Limit to 10,000 QA pairs for faster training (optional)
if len(records) > 10000:
    print(f"Limiting training data from {len(records)} to 10,000 examples")
    records = random.sample(records, 10000)

# =================================================================================
# 2️⃣ Create Dataset and Validation Split
# =================================================================================
dataset = Dataset.from_list(records)
split = dataset.train_test_split(test_size=VAL_SPLIT, seed=SEED)
train_dataset = split["train"]
eval_dataset = split["test"]

print(f"Train size: {len(train_dataset)}, Eval size: {len(eval_dataset)}")

# =================================================================================
# 3️⃣ Load Tokenizer & Quantized Base Model for QLoRA
# =================================================================================
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True, use_fast=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    load_in_4bit=True,
    device_map="auto",
    trust_remote_code=True
)
model = prepare_model_for_kbit_training(model)

# =================================================================================
# 4️⃣ Prepare LoRA Adapters
# =================================================================================
lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)
model = get_peft_model(model, lora_config)

# =================================================================================
# 5️⃣ Tokenize Dataset
# =================================================================================
def tokenize_function(examples):
    return tokenizer(
        examples["prompt"],
        text_target=examples["response"],
        truncation="longest_first",
        padding="max_length",
        max_length=2048
    )

train_tokenized = train_dataset.map(tokenize_function, batched=True)
eval_tokenized = eval_dataset.map(tokenize_function, batched=True)

# =================================================================================
# 6️⃣ Set up Trainer
# =================================================================================
training_args = TrainingArguments(
    output_dir=MODEL_OUT_DIR,
    num_train_epochs=EPOCHS,
    per_device_train_batch_size=BATCH_SIZE,
    gradient_accumulation_steps=GRADIENT_ACCUMULATION_STEPS,
    learning_rate=LEARNING_RATE,
    warmup_ratio=WARMUP_RATIO,
    fp16=True,
    save_total_limit=2,
    save_strategy="epoch",
    logging_steps=50,
    weight_decay=0.01,
    max_grad_norm=0.3,
    lr_scheduler_type="cosine",
    report_to="none"
)

# =================================================================================
# 7️⃣ Trainer and Training
# =================================================================================
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_tokenized
    # Removed eval_dataset since we're not using evaluation strategy
)

trainer.train()

# =================================================================================
# 8️⃣ Save Final Adapter Weights and Tokenizer
# =================================================================================
model.save_pretrained(MODEL_OUT_DIR, safe_serialization=True)
tokenizer.save_pretrained(MODEL_OUT_DIR)
print(f"✅ Done! Saved trained QLoRA adapter weights and tokenizer to {MODEL_OUT_DIR}")
