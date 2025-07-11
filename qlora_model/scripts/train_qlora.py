#!/usr/bin/env python3
"""
================================================================================
train_qlora.py

This script fine-tunes a Mistral-7B (or compatible) model
using LoRA on your structured Q&A pairs about X.509 certificates.

Steps:
  - Loads JSON data from training_data/qa_pairs.json
  - Tokenizes question+context as input, expecting answer as label
  - Trains with PEFT QLoRA on bitsandbytes 4-bit quantized model
  - Saves trained adapter weights in safetensors format

Author: Mihir Gupta, 2025
For AI Certificate Service POC (PKISecOPS project)
================================================================================
"""

import json
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer
from peft import prepare_model_for_kbit_training, LoraConfig, get_peft_model
import torch

# Paths
DATA_FILE = "../training_data/qa_pairs.json"
MODEL_OUT_DIR = "../model_weights/"

# Hyperparams
MODEL_NAME = "facebook/opt-1.3b"  # Using a smaller model that can fit in memory
BATCH_SIZE = 4
EPOCHS = 3
LEARNING_RATE = 2e-4

# =================================================================================
# 1️⃣ Load your JSON data and convert to HF dataset
# =================================================================================
with open(DATA_FILE, "r") as f:
    data = json.load(f)

# We'll join question + context for training input
records = [{
    "prompt": f"Question: {item['question']}\nCertificate:\n{item['context']}",
    "response": item["answer"]
} for item in data]

dataset = Dataset.from_list(records)

# =================================================================================
# 2️⃣ Load tokenizer & base model
# =================================================================================
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    # No device_map or torch_dtype - use default CPU
)

# =================================================================================
# 3️⃣ Prepare model for LoRA (PEFT) training
# =================================================================================

lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],  # typical for LLaMA/Mistral
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)
model = get_peft_model(model, lora_config)

# =================================================================================
# 4️⃣ Tokenize dataset
# =================================================================================
def tokenize_function(examples):
    return tokenizer(
        examples["prompt"],
        text_target=examples["response"],
        truncation=True,
        padding="max_length",
        max_length=512
    )

tokenized_dataset = dataset.map(tokenize_function, batched=True)

# =================================================================================
# 5️⃣ Set up training
# =================================================================================
training_args = TrainingArguments(
    output_dir=MODEL_OUT_DIR,
    per_device_train_batch_size=BATCH_SIZE,
    num_train_epochs=EPOCHS,
    learning_rate=LEARNING_RATE,
    fp16=False,
    save_total_limit=2,
    save_strategy="epoch",
    logging_steps=10,
    report_to="none"
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset
)

# =================================================================================
# 6️⃣ Train!
# =================================================================================
trainer.train()

# =================================================================================
# 7️⃣ Save final adapter weights
# =================================================================================
model.save_pretrained(MODEL_OUT_DIR, safe_serialization=True)
print(f"✅ Done! Saved trained QLoRA adapter weights to {MODEL_OUT_DIR}")
