#!/usr/bin/env python3
"""
================================================================================
train_qlora.py

Fine-tunes Mistral-7B with QLoRA on your structured X.509 cert Q&A pairs.

- Loads JSON data from training_data/qa_pairs.json
- Tokenizes question+context as input, expects answer as label
- Trains with PEFT QLoRA on bitsandbytes 4-bit quantized model
- Saves adapter weights in safetensors format

Author: Mihir Gupta, 2025
For AI Certificate Service POC (PKISecOPS project)
================================================================================
"""

import json
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer
from peft import prepare_model_for_kbit_training, LoraConfig, get_peft_model
import torch

# =================================================================================
# Paths & Hyperparams
# =================================================================================
DATA_FILE = "../training_data/qa_pairs.json"
MODEL_OUT_DIR = "../model_weights/"

MODEL_NAME = "mistralai/Mistral-7B-Instruct-v0.1"
BATCH_SIZE = 4
EPOCHS = 3
LEARNING_RATE = 2e-4

# =================================================================================
# 1️⃣ Load your JSON data
# =================================================================================
with open(DATA_FILE, "r") as f:
    data = json.load(f)

records = [{
    "prompt": f"Question: {item['question']}\nCertificate:\n{item['context']}",
    "response": item["answer"]
} for item in data]

dataset = Dataset.from_list(records)

# =================================================================================
# 2️⃣ Load tokenizer & quantized base model for QLoRA
# =================================================================================
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    load_in_4bit=True,
    device_map="auto"
)
model = prepare_model_for_kbit_training(model)

# =================================================================================
# 3️⃣ Prepare LoRA adapters
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
# 5️⃣ Set up Trainer
# =================================================================================
training_args = TrainingArguments(
    output_dir=MODEL_OUT_DIR,
    per_device_train_batch_size=BATCH_SIZE,
    num_train_epochs=EPOCHS,
    learning_rate=LEARNING_RATE,
    fp16=True,
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
