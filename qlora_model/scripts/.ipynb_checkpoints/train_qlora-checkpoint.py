#!/usr/bin/env python3
"""
================================================================================
train_qlora.py

Fine-tunes Mistral-7B on X.509 flaw detection using QLoRA.
Inspired by your large DDP project, but built cleanly with torch DataLoader.

Author: Mihir Gupta, 2025
================================================================================
"""

import json
import torch
from torch.utils.data import DataLoader
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import load_dataset
from tqdm import tqdm

# =================================================================================
# Configuration
# =================================================================================
MODEL_ID = "mistralai/Mistral-7B-Instruct-v0.1"
TRAIN_JSONL = "../data/train.jsonl"
RUN_DIR = "../model_weights"
BATCH_SIZE = 2
MAX_LENGTH = 2048
LR = 2e-4
WEIGHT_DECAY = 0.01
MAX_EPOCHS = 3
GRAD_CLIP = 1.0

# =================================================================================
# Load dataset
# =================================================================================
dataset = load_dataset('json', data_files=TRAIN_JSONL, split='train')

# =================================================================================
# Tokenizer
# =================================================================================
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
tokenizer.pad_token = tokenizer.eos_token

# =================================================================================
# Collate function (like your inspiration's build_data_loader)
# =================================================================================
def collate_fn(batch):
    prompts = []
    for f in batch:
        user_text = f["messages"][0]["content"]
        assistant_text = f["messages"][1]["content"]
        # Wrap in instruction format for Mistral
        prompts.append(f"<s>[INST] {user_text} [/INST] {assistant_text}</s>")

    encodings = tokenizer(
        prompts,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=MAX_LENGTH
    )
    encodings["labels"] = encodings["input_ids"].clone()
    return encodings

loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True, collate_fn=collate_fn)

# =================================================================================
# Load quantized model with LoRA
# =================================================================================
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    quantization_config=bnb_config,
    device_map="auto"
)

model = prepare_model_for_kbit_training(model)

lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)

model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# =================================================================================
# Optimizer and scheduler
# =================================================================================
optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=MAX_EPOCHS * len(loader))

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.train()

# =================================================================================
# Training loop
# =================================================================================
for epoch in range(MAX_EPOCHS):
    epoch_loss = 0.0
    progress = tqdm(loader, desc=f"Epoch {epoch+1}/{MAX_EPOCHS}")

    for batch in progress:
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["labels"].to(device)

        outputs = model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            labels=labels
        )
        loss = outputs.loss

        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
        optimizer.step()
        scheduler.step()

        loss_val = loss.item()
        epoch_loss += loss_val
        progress.set_postfix(loss=loss_val)

    avg_epoch_loss = epoch_loss / len(loader)
    print(f"✅ Epoch {epoch+1} avg loss: {avg_epoch_loss:.4f}")

# =================================================================================
# Save only LoRA adapter weights
# =================================================================================
print(f"✅ Saving model adapter weights to {RUN_DIR}")
model.save_pretrained(RUN_DIR, safe_serialization=True)
tokenizer.save_pretrained(RUN_DIR)
print("✅ Training complete!")
