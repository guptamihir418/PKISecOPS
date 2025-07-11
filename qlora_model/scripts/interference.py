#!/usr/bin/env python3
"""
================================================================================
inference.py

Loads your fine-tuned QLoRA adapter on top of the base LLaMA/Mistral 7B,
and runs a simple interactive inference loop.

Author: Mihir Gupta, 2025
================================================================================
"""

from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
from peft import PeftModel
import torch

# Paths
BASE_MODEL = "mistralai/Mistral-7B-Instruct-v0.1"  # or "mistralai/Mistral-7B-v0.1"
ADAPTER_DIR = "../model_weights/"

# Load tokenizer + base model
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
tokenizer.pad_token = tokenizer.eos_token

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    load_in_4bit=True,
    device_map="auto"
)

# Load your fine-tuned QLoRA adapter
model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)

# Set up pipeline
pipe = pipeline("text-generation", model=model, tokenizer=tokenizer, device=0 if torch.cuda.is_available() else -1)

# =================================================================================
# Interactive loop
# =================================================================================
print("\n✅ QLoRA Cert Inspector Ready! Type 'exit' to quit.")
while True:
    question = input("\nEnter your question (about cert flaws): ").strip()
    if question.lower() in ["exit", "quit"]:
        break

    # Example stub PEM context
    cert_context = """
-----BEGIN CERTIFICATE-----
MIIDWjCCAsOgAwIBAgIUL1M/vYxrrfKIeeVyePEBEThvDsUwDQYJKoZIhvcNAQEF
...
-----END CERTIFICATE-----
"""
    prompt = f"Question: {question}\nCertificate:\n{cert_context}"

    output = pipe(prompt, max_new_tokens=100, do_sample=True, top_p=0.9, temperature=0.7)[0]["generated_text"]
    print("\n--- Answer ---")
    print(output[len(prompt):].strip())  # Print only the new text
